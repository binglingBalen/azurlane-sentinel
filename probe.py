#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""碧蓝航线国服 · 版本哨兵（GitHub Actions 版，单文件自包含）

跑在 GitHub Actions 的 runner 上，**完全不需要你自己的电脑开机**：

  1. 对游戏登录服做 **653 字节裸 TCP 握手** → 提取 $azhash$ 版本指纹
  2. 与仓库里的 state.json 比对
  3. **有变化 → SMTP 发邮件推送**（新版本、旧版本、检测时间）+ 更新 state.json 并提交
  4. 无变化 → 静默退出（每天第一次运行时写一次心跳，用于避开"60 天无活动禁用 cron"）

为什么用握手而不是拉完整清单：登录服响应 **653 字节**，而 check() 要下 **4.05 MB**
（6200 倍差距）。10 分钟一轮 ≈ 每天 90 KB。

零依赖：只用 Python 标准库（云端没有你那套 alz 工具链）。

环境变量（全部从 GitHub Secrets 注入，绝不写进仓库）：
  SMTP_HOST   smtp.qq.com
  SMTP_PORT   465
  SMTP_USER   发件邮箱
  SMTP_AUTH   授权码（不是登录密码！QQ 邮箱在 设置→账号 里开启 SMTP 后获取）
  MAIL_TO     收件邮箱，多个用逗号分隔

本地测试（需要有网络）：
  python probe.py --test-conn    只握手 + 打印结果（不发信、不改 state）
  python probe.py --test-mail    握手 + 真发一封测试邮件
  python probe.py --dry-run      握手 + 比对 + 打印（不发信、不落盘）

退出码：0 正常；非 0 表示握手/邮件失败（Actions 里会标红，便于你发现）
"""
import argparse
import json
import os
import re
import smtplib
import socket
import ssl
import sys
import time
from datetime import datetime, timedelta, timezone
from email.header import Header
from email.mime.text import MIMEText
from email.utils import formataddr

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

LOGIN_HOST = "line1-login-bili-blhx.bilibiligame.net"
LOGIN_PORT = 80
LOGIN_HEX = "000a002a300000083d120130"      # 与游戏客户端检查更新时发的包一致
HERE = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(HERE, "state.json")
LOCAL_STATUS_FILE = os.path.join(HERE, "local-status.json")   # 本机上报（本机写）
TASK_FILE = os.path.join(HERE, "task.json")                   # 任务下发（云端写）
CST = timezone(timedelta(hours=8))
AZHASH_RE = re.compile(r"\$azhash\$(\d+)\$(\d+)\$(\d+)\$([0-9a-f]+)")
OFFLINE_SEC = 15 * 60      # 本机超过这么久没上报 → 视为离线，不下发任务
                           # （本机守护器默认 5 分钟一轮，15 分钟 = 容许连丢两轮）
APK_RE = re.compile(r"https?://[^\"\s]+")

# 本地调试用：**只有显式设置 ALZ_LOCAL_MAIL_CFG 环境变量**指向 alz 的「邮件配置.json」
# 才会回退读它。云端（GitHub Actions）不设这个变量 → 只认 Secrets，
# 既不会去读你本机路径，也不会把本地路径带进仓库。
LOCAL_MAIL_CFG = os.environ.get("ALZ_LOCAL_MAIL_CFG")


def now_cst():
    return datetime.now(CST).strftime("%Y-%m-%d %H:%M:%S")


def log(msg):
    print(f"[{now_cst()}] {msg}", flush=True)


# --------------------------------------------------------------------------
# 握手（与 alz/AzurLane.fetch_live_manifest_names 同协议）
# --------------------------------------------------------------------------
def handshake(timeout=12.0, settle=0.4):
    """裸 TCP 握手登录服 → dict。

    收包策略：一旦数据里出现 $azhash$ 立即返回；没拿到就等到 timeout 或服务端关连接
    （不要按"静默即收完"提前退出——那会把分片响应截断，本地实测踩过）。
    """
    t0 = time.perf_counter()
    data = b""
    try:
        with socket.create_connection((LOGIN_HOST, LOGIN_PORT), timeout=timeout) as s:
            s.settimeout(settle)
            s.sendall(bytes.fromhex(LOGIN_HEX))
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    if b"$azhash$" in data:
                        break
                    continue
                if not chunk:
                    break
                data += chunk
                if b"$azhash$" in data:
                    break
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}",
                "bytes": len(data), "elapsed": time.perf_counter() - t0}

    txt = data.decode("utf-8", "ignore")
    m = AZHASH_RE.search(txt)
    apks = APK_RE.findall(txt)
    return {
        "ok": bool(m),
        "azhash": m.group(0) if m else None,
        "version": ".".join(m.groups()[:3]) if m else None,
        "apk": apks[0] if apks else None,
        "bytes": len(data),
        "elapsed": time.perf_counter() - t0,
        "error": None if m else "响应中未匹配到 $azhash$ 指纹",
        "raw": txt[:300],
    }


# --------------------------------------------------------------------------
# 状态
# --------------------------------------------------------------------------
def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"_说明": "版本哨兵状态。azhash = 上次观测到的版本指纹；history = 变化历史。",
                "azhash": None, "version": None, "changes": 0,
                "history": [], "last_alive": None}


def save_state(st):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------
# 端云同步：读本机上报状态 → 决定是否下发任务
# --------------------------------------------------------------------------
def load_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default if default is not None else {}


def save_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def parse_cst(s):
    try:
        return datetime.strptime(str(s), "%Y-%m-%d %H:%M:%S").replace(tzinfo=CST)
    except Exception:
        return None


def local_status():
    """本机上报的状态（本机写、云端读）。"""
    return load_json(LOCAL_STATUS_FILE) or {}


def prev_task():
    """上一次下发的任务（用于去重）。"""
    return load_json(TASK_FILE) or {}


def evaluate(hs, ls, task):
    """核心决策：本机这次该不该收到任务？→ (action, reason)

    action ∈ issue / already_issued / skip，按优先级：

      1. 本机从未上报           → skip      （端云同步端还没部署）
      2. online_at 过期          → skip      （离线。本机上线后自己的握手自检会补跑，
                                              所以离线时下发没意义——没人接）
      3. busy 或 phase!=done     → skip      （正在反编译，不能打断）
      4. 本机指纹 == 云端指纹     → skip      （已最新。这一条天然覆盖『版本号相同但
                                              内容变化』：国服会在版本号不变时推内容，
                                              此时 $azhash$ 里的内容 hash 会变）
      5. 同目标任务已下发未完成   → already_issued（避免每 10 分钟重复下发＋重复发信）
      6. 其余（本机确实落后）     → issue
    """
    if not ls or not ls.get("online_at"):
        return "skip", "本机从未上报状态（端云同步端未部署）"

    t = parse_cst(ls.get("online_at"))
    if t is None:
        return "skip", f"本机 online_at 无法解析：{ls.get('online_at')!r}"
    age = (datetime.now(CST) - t).total_seconds()
    if age > OFFLINE_SEC:
        return "skip", (f"本机离线（{age / 60:.1f} 分钟未上报，阈值 {OFFLINE_SEC // 60} 分钟）；"
                        f"本机上线后会用自己的握手自检补跑")

    if ls.get("busy") or (ls.get("phase") not in (None, "done")):
        return "skip", f"本机正在反编译（phase={ls.get('phase')}，busy={ls.get('busy')}）"

    if ls.get("azhash") == hs.get("azhash"):
        return "skip", f"本机已是最新（{ls.get('version')}，指纹与云端一致）"

    if (task.get("status") in ("pending", "running")
            and task.get("target_azhash") == hs.get("azhash")):
        return "already_issued", (f"任务 {task.get('id')} 已处于 {task.get('status')}"
                                  f"（目标 {task.get('target_version')}），不重复下发")

    return "issue", (f"本机 {ls.get('version') or '(未知)'} 落后于云端 {hs.get('version')}"
                     f"（本机 {str(ls.get('azhash'))[-16:]} → 云端 {str(hs.get('azhash'))[-16:]}）")


def build_task(hs, ls):
    """构造下发任务；id 含目标版本 + 指纹尾 8 位，便于去重与追踪。"""
    tail = str(hs.get("azhash") or "unknown").split("$")[-1][:8]
    return {
        "id": f"task-{hs.get('version', 'x')}-{tail}",
        "action": "hotupdate",
        "target_azhash": hs.get("azhash"),
        "target_version": hs.get("version"),
        "from_azhash": ls.get("azhash"),
        "from_version": ls.get("version"),
        "issued_at": now_cst(),
        "issued_reason": f"本机 {ls.get('version')} 落后于云端 {hs.get('version')}",
        "status": "pending",
        "claimed_at": None,
        "finished_at": None,
        "result": None,
        "updated_at": now_cst(),
    }


# --------------------------------------------------------------------------
# 邮件
# --------------------------------------------------------------------------
def mail_config():
    cfg = {
        "host": os.environ.get("SMTP_HOST", ""),
        "port": int(os.environ.get("SMTP_PORT") or 0),
        "user": os.environ.get("SMTP_USER", ""),
        "auth": os.environ.get("SMTP_AUTH", ""),
        "to": [x.strip() for x in (os.environ.get("MAIL_TO") or "").split(",") if x.strip()],
    }
    if cfg["host"] and cfg["user"] and cfg["auth"] and cfg["to"]:
        return cfg
    # 本地回退：仅在显式给了 ALZ_LOCAL_MAIL_CFG 时读本机 alz 邮件配置（调试用）
    if LOCAL_MAIL_CFG and not (cfg["host"] and cfg["user"] and cfg["auth"] and cfg["to"]):
        try:
            with open(LOCAL_MAIL_CFG, encoding="utf-8") as f:
                local = json.load(f)
            cfg["host"] = cfg["host"] or local.get("smtp_host", "")
            cfg["port"] = cfg["port"] or int(local.get("smtp_port") or 465)
            cfg["user"] = cfg["user"] or local.get("sender", "")
            cfg["auth"] = cfg["auth"] or local.get("auth_code", "")
            if not cfg["to"]:
                cfg["to"] = list(local.get("recipients") or [])
            cfg["_source"] = f"本地 {LOCAL_MAIL_CFG}"
        except Exception as e:
            cfg["_source"] = f"本地配置读取失败：{type(e).__name__}: {e}"
    return cfg


def send_mail(subject, body, cfg, dry=False):
    if dry:
        log(f"[dry-run] 本应发邮件：{subject}")
        return True
    if not (cfg.get("host") and cfg.get("user") and cfg.get("auth") and cfg.get("to")):
        log("✖ 邮件配置不完整（缺 SMTP_HOST/SMTP_USER/SMTP_AUTH/MAIL_TO）→ 跳过发送")
        return False
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = Header(subject, "utf-8")
    # ⚠ 必须用 formataddr 把「显示名」和「地址」分开：
    #   写成 Header(f"名字 <{addr}>") 会把连地址一起做 RFC2047 编码，
    #   QQ 邮箱判定 From 头无有效地址 → 550 拒收（已在真实运行中踩到）。
    msg["From"] = formataddr(("碧蓝版本哨兵", cfg["user"]))
    msg["To"] = ", ".join(cfg["to"])
    try:
        with smtplib.SMTP_SSL(cfg["host"], int(cfg.get("port") or 465),
                              context=ssl.create_default_context(), timeout=30) as s:
            s.login(cfg["user"], cfg["auth"])
            s.sendmail(cfg["user"], cfg["to"], msg.as_string())
        log(f"✔ 邮件已发送 → {', '.join(cfg['to'])}（配置来源：{cfg.get('_source', '环境变量/Secrets')}）")
        return True
    except Exception as e:
        log(f"✖ 邮件发送失败：{type(e).__name__}: {e}")
        return False


def build_change_mail(hs, st, ls, action, reason, issued, changed):
    old_v = st.get("version") or "(无记录)"
    old_a = st.get("azhash") or "(无记录)"
    if changed:
        subject = f"【碧蓝航线】检测到热更新 {hs['version']}（原 {old_v}）"
    elif action == "issue":
        subject = f"【碧蓝航线】已向本机下发拆包任务 {hs['version']}"
    else:
        subject = f"【碧蓝航线】版本状态更新 {hs['version']}"

    busy = bool(ls.get("busy")) or (ls.get("phase") not in (None, "done"))
    lines = [
        "碧蓝航线国服 · 版本哨兵（云端 GitHub Actions）",
        "=" * 46,
        f"检测时间 : {now_cst()} (北京时间)",
        f"云端版本 : {hs['version']}",
        f"云端指纹 : {hs['azhash']}",
        f"上次记录 : {old_v} / {old_a}",
        "",
        "── 本机状态（由本机上报）──",
        f"上报时间 : {ls.get('online_at') or '(从未上报)'}",
        f"本机版本 : {ls.get('version') or '(未知)'}",
        f"本机指纹 : {ls.get('azhash') or '(未知)'}",
        f"忙闲     : {'反编译中（phase=' + str(ls.get('phase')) + '）' if busy else '空闲'}",
        "",
        "── 端云决策 ──",
        f"判定     : {action}",
        f"原因     : {reason}",
    ]
    if issued:
        lines += [
            "",
            f"★ 已下发任务：{issued['id']}",
            f"  目标版本 : {issued['target_version']}",
            f"  目标指纹 : {issued['target_azhash']}",
            f"  APK      : {hs.get('apk') or '(未取到)'}",
            "  本机将在下一次轮询领到该任务并自动执行反编译，完成后会再发一封结果邮件。",
        ]
    else:
        lines += ["", "（本次未下发任务）"]
    lines += [
        "",
        f"握手开销 : {hs['bytes']} 字节 / {hs['elapsed']:.2f} 秒",
        "",
        "说明：云端只做「检测 + 决策 + 通知」，反编译仍在你的电脑上执行（runner 没有你的工具链）。",
        "— 由 GitHub Actions 自动发出",
    ]
    return subject, "\n".join(lines)


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="碧蓝航线国服版本哨兵（GitHub Actions 版）")
    ap.add_argument("--test-conn", action="store_true", help="只握手并打印结果")
    ap.add_argument("--test-smtp", action="store_true", help="只验证 SMTP 登录（不发信）")
    ap.add_argument("--test-mail", action="store_true", help="握手 + 真发一封测试邮件")
    ap.add_argument("--dry-run", action="store_true", help="握手+比对+打印，不发信不落盘")
    args = ap.parse_args()

    cfg = mail_config()
    if not cfg.get("_source"):
        log(f"邮件配置：{cfg['host']}:{cfg['port']} → {cfg['to']}")

    if args.test_smtp:
        if not (cfg.get("host") and cfg.get("user") and cfg.get("auth") and cfg.get("to")):
            log(f"✖ 邮件配置不完整：host={cfg.get('host')!r} user={cfg.get('user')!r} "
                f"auth={'已设置' if cfg.get('auth') else '缺失'} to={cfg.get('to')}")
            return 1
        try:
            with smtplib.SMTP_SSL(cfg["host"], int(cfg.get("port") or 465),
                                  context=ssl.create_default_context(), timeout=30) as s:
                s.login(cfg["user"], cfg["auth"])
            log(f"✔ SMTP 登录成功（未发信）：{cfg['host']}:{cfg.get('port') or 465} "
                f"as {cfg['user']} → {cfg['to']}")
            return 0
        except Exception as e:
            log(f"✖ SMTP 登录失败：{type(e).__name__}: {e}")
            return 1

    hs = handshake()
    log(f"握手：{hs['bytes']} 字节 / {hs['elapsed']:.2f}s  版本={hs.get('version')}  "
        f"指纹={hs.get('azhash')}")
    if hs.get("error"):
        log(f"⚠ {hs['error']}   响应片段: {hs.get('raw', '')[:160]!r}")

    if args.test_conn:
        log("OK" if hs["ok"] else "FAIL（这个 runner 连不上登录服，就得换方案）")
        return 0 if hs["ok"] else 1

    if args.test_mail:
        ok = send_mail("【碧蓝航线】版本哨兵测试邮件",
                       f"这是一封测试邮件。\n检测时间: {now_cst()}\n"
                       f"握手结果: {hs.get('version')} ({hs.get('azhash')})\n"
                       f"握手开销: {hs['bytes']} 字节 / {hs['elapsed']:.2f}s\n",
                       cfg, dry=args.dry_run)
        return 0 if ok else 1

    if not hs["ok"]:
        log("✖ 握手失败 → 不改状态、不发信（避免误报）。本次退出码 1。")
        return 1

    st = load_state()
    old = st.get("azhash")
    today = datetime.now(CST).strftime("%Y-%m-%d")

    first_run = old is None
    if first_run:
        # 首次运行：只建立基线。否则第一封邮件就是「检测到热更新」的误报。
        log(f"首次运行：建立基线 {hs['azhash']}（version {hs['version']}），不发信")
        st["azhash"] = hs["azhash"]
        st["version"] = hs["version"]
        st["first_seen"] = st.get("first_seen") or now_cst()
    changed = (not first_run) and (old != hs["azhash"])

    if changed:
        st["changes"] = int(st.get("changes") or 0) + 1
        st.setdefault("history", []).append(
            {"azhash": hs["azhash"], "version": hs["version"], "at": now_cst(),
             "from": old})
        st["history"] = st["history"][-200:]
        st["azhash"] = hs["azhash"]
        st["version"] = hs["version"]
        st["first_seen"] = st.get("first_seen") or now_cst()
        st["last_change"] = now_cst()
        log(f"★ 云端版本变化：{old} → {hs['azhash']}")
    elif not first_run:
        log(f"云端无变化（仍为 {hs['version']}）")

    # ---- 端云决策：**每轮都做**，不能只在「云端检测到变化」时做 ----
    #   否则「本机落后、但云端基线早已是新版本」这种情况永远补不上（那时 changed=False）。
    ls = local_status()
    task = prev_task()
    action, reason = evaluate(hs, ls, task)
    issued = None
    if action == "issue":
        issued = build_task(hs, ls)
        log(f"★ 端云决策：下发任务 {issued['id']} — {reason}")
    else:
        log(f"端云决策：{action} — {reason}")

    # ---- 通知：有版本变化，或本次新下发了任务（其余静默，避免每 10 分钟一封）----
    if changed or action == "issue":
        subject, body = build_change_mail(hs, st, ls, action, reason, issued, changed)
        if not args.dry_run:
            send_mail(subject, body, cfg)
        else:
            log(f"[dry-run] 本应发：{subject}")
    else:
        log("本次不发邮件（云端无变化 且 未下发新任务）")

    # 每天一次心跳：让仓库保持"有活动"，避免 scheduled workflow 因 60 天无活动被禁用
    if st.get("last_alive") != today:
        st["last_alive"] = today
        log(f"心跳已更新（{today}）")

    if not args.dry_run:
        save_state(st)
        log("state.json 已更新")
        if issued:
            save_json(TASK_FILE, issued)
            log(f"task.json 已更新（{issued['id']} / status=pending）→ 本机下次轮询会领到")
    else:
        log("[dry-run] 未落盘")
    return 0


if __name__ == "__main__":
    sys.exit(main())

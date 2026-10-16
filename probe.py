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
CST = timezone(timedelta(hours=8))
AZHASH_RE = re.compile(r"\$azhash\$(\d+)\$(\d+)\$(\d+)\$([0-9a-f]+)")
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


def build_change_mail(hs, st):
    old_v = st.get("version") or "(无记录)"
    old_a = st.get("azhash") or "(无记录)"
    subject = f"【碧蓝航线】检测到热更新 {hs['version']}（原 {old_v}）"
    body = "\n".join([
        "碧蓝航线国服 · 版本哨兵（云端 GitHub Actions）",
        "=" * 46,
        f"检测时间 : {now_cst()} (北京时间)",
        f"新版本   : {hs['version']}",
        f"新指纹   : {hs['azhash']}",
        f"上次版本 : {old_v}",
        f"上次指纹 : {old_a}",
        f"累计变化 : {st.get('changes', 0) + 1} 次",
        "",
        f"安装包   : {hs.get('apk') or '(未取到)'}",
        f"握手开销 : {hs['bytes']} 字节 / {hs['elapsed']:.2f} 秒",
        "",
        "说明：本哨兵只做「检测 + 通知」，不下载、不反编译（GitHub runner 无你的工具链）。",
        "      本机守护器开机后会自己发现落后并自动补跑；你也可以手动执行 alz.hotupdate()。",
        "",
        f"— 由 GitHub Actions 自动发出 · state.json 已更新",
    ])
    return subject, body


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
        subject, body = build_change_mail(hs, st)
        log(f"★ 版本变化：{old} → {hs['azhash']}")
        if not args.dry_run:
            send_mail(subject, body, cfg)
        else:
            log(f"[dry-run] 本应发：{subject}")
    elif not first_run:
        log(f"无变化（仍为 {hs['version']}）")

    # 每天一次心跳：让仓库保持"有活动"，避免 scheduled workflow 因 60 天无活动被禁用
    if st.get("last_alive") != today:
        st["last_alive"] = today
        log(f"心跳已更新（{today}）")

    if not args.dry_run:
        save_state(st)
        log("state.json 已更新")
    else:
        log("[dry-run] 未落盘")
    return 0


if __name__ == "__main__":
    sys.exit(main())

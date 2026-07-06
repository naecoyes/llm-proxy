#!/usr/bin/env python3
"""Nscan Proxy 启动脚本"""

import argparse
import logging
import sys
from pathlib import Path

import uvicorn


def setup_logging(level: str = "info"):
    """设置日志"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main():
    parser = argparse.ArgumentParser(description="Nscan Proxy Server")
    parser.add_argument(
        "--config",
        "-c",
        type=str,
        default="proxy_config.yaml",
        help="配置文件路径 (默认: proxy_config.yaml)",
    )
    parser.add_argument(
        "--host", type=str, default=None, help="监听地址 (默认: 使用配置文件中的值)"
    )
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=None,
        help="监听端口 (默认: 使用配置文件中的值)",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=None,
        choices=["debug", "info", "warning", "error"],
        help="日志级别 (默认: 使用配置文件中的值)",
    )
    parser.add_argument("--reload", action="store_true", help="启用自动重载 (开发模式)")

    args = parser.parse_args()

    # 检查配置文件
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"错误: 配置文件不存在: {config_path}")
        sys.exit(1)

    # 加载配置获取默认值
    import yaml

    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    server_config = config.get("server", {})
    host = args.host or server_config.get("host", "127.0.0.1")
    port = args.port or server_config.get("port", 8888)
    log_level = args.log_level or server_config.get("log_level", "info")

    # 设置日志
    setup_logging(log_level)

    logger = logging.getLogger(__name__)
    logger.info("启动 Nscan Proxy Server")
    logger.info(f"配置文件: {config_path.absolute()}")
    logger.info(f"监听地址: {host}:{port}")
    logger.info(f"日志级别: {log_level}")

    # 设置环境变量跳过所有 LLM 的代理
    import os
    os.environ["NO_PROXY"] = "*"
    os.environ["no_proxy"] = "*"

    # 创建应用
    from server import create_app

    app = create_app(str(config_path.absolute()))

    # 启动服务
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=log_level,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()

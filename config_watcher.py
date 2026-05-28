"""配置热加载 - 监控配置文件变化并自动重载"""

import logging
import threading
import time
from pathlib import Path
from typing import Callable, Optional

import yaml

logger = logging.getLogger(__name__)


class ConfigWatcher:
    """监控配置文件变化并自动重载"""

    def __init__(self, config_path: str, on_config_change: Callable[[dict], None]):
        """
        Args:
            config_path: 配置文件路径
            on_config_change: 配置变化时的回调函数，接收新配置作为参数
        """
        self.config_path = Path(config_path)
        self.on_config_change = on_config_change
        self.last_modified: float = 0
        self.last_config: Optional[dict] = None
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.check_interval = 2.0  # 检查间隔（秒）

    def load_config(self) -> dict:
        """加载配置文件

        Returns:
            配置字典

        Raises:
            FileNotFoundError: 配置文件不存在
            yaml.YAMLError: 配置文件格式错误
        """
        if not self.config_path.exists():
            raise FileNotFoundError(f"配置文件不存在: {self.config_path}")

        with open(self.config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)

        if not isinstance(config, dict):
            raise ValueError(f"配置文件格式错误: {self.config_path}")

        return config

    def check_and_reload(self) -> bool:
        """检查配置文件是否变化，如有变化则重载

        Returns:
            True 表示配置已重载
        """
        try:
            current_modified = self.config_path.stat().st_mtime

            if current_modified <= self.last_modified:
                return False

            # 文件已修改，加载新配置
            new_config = self.load_config()

            # 更新状态
            self.last_modified = current_modified
            self.last_config = new_config

            # 调用回调
            logger.info(f"配置文件已更新: {self.config_path}")
            self.on_config_change(new_config)

            return True

        except Exception as e:
            logger.error(f"检查配置文件失败: {e}")
            return False

    def _watch_loop(self):
        """监控循环"""
        logger.info(f"开始监控配置文件: {self.config_path}")

        while self.running:
            self.check_and_reload()
            time.sleep(self.check_interval)

        logger.info("停止监控配置文件")

    def start(self):
        """启动监控"""
        if self.running:
            return

        # 初始加载
        try:
            self.last_config = self.load_config()
            self.last_modified = self.config_path.stat().st_mtime
        except Exception as e:
            logger.error(f"初始加载配置失败: {e}")
            raise

        # 启动监控线程
        self.running = True
        self.thread = threading.Thread(target=self._watch_loop, daemon=True)
        self.thread.start()

    def stop(self):
        """停止监控"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
            self.thread = None

    def get_config(self) -> dict:
        """获取当前配置"""
        if self.last_config is None:
            self.last_config = self.load_config()
        return self.last_config

    def get_status(self) -> dict:
        """返回监控状态"""
        return {
            "config_path": str(self.config_path),
            "running": self.running,
            "last_modified": self.last_modified,
            "check_interval": self.check_interval,
        }

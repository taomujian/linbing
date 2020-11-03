import importlib
from app.oneforall.config import default


class Settings(object):
    def __init__(self):
        # 获取全局变量中的配置信息
        for attr in dir(default):
            setattr(self, attr, getattr(default, attr))
        setting_modules = ['app.oneforall.config.setting', 'app.oneforall.config.api']
        for setting_module in setting_modules:
            setting = importlib.import_module(setting_module)
            for attr in dir(setting):
                setattr(self, attr, getattr(setting, attr))


settings = Settings()

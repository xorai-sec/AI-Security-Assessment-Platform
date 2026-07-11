from workers.common.base_runner import BaseFrameworkRunner
from workers.common.server import create_worker_app


class NativeRunner(BaseFrameworkRunner):
    framework_name = "native"
    package_name = None


app = create_worker_app(NativeRunner())


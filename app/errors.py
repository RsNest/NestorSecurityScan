"""Human-readable Russian error messages."""

from __future__ import annotations


class ScannerError(Exception):
    """Base scanner error with a user-facing Russian message."""

    def __init__(self, message: str, *, detail: str | None = None):
        self.message = message
        self.detail = detail
        super().__init__(message)


class ImageReferenceError(ScannerError):
    pass


class RegistryAuthError(ScannerError):
    pass


class RegistryNotFoundError(ScannerError):
    pass


class RegistryTLSError(ScannerError):
    pass


class ToolTimeoutError(ScannerError):
    pass


class ToolExecutionError(ScannerError):
    pass


class PolicyError(ScannerError):
    pass


class HarborError(ScannerError):
    pass


class RegistryError(ScannerError):
    pass


def map_subprocess_error(tool: str, stderr: str, returncode: int | None = None) -> ScannerError:
    text = (stderr or "").lower()
    if "unauthorized" in text or "401" in text or "authentication required" in text:
        return RegistryAuthError(
            "Неверные credentials для registry. Проверьте username/password "
            "или robot account и права Pull Repository."
        )
    if "certificate" in text or "x509" in text or "tls" in text:
        return RegistryTLSError(
            "Ошибка проверки TLS-сертификата registry. "
            "Проверьте CA в /certs или отключите проверку TLS только для теста."
        )
    if "manifest unknown" in text or "not found" in text or "404" in text:
        return RegistryNotFoundError(
            "Образ не найден (manifest unknown). Проверьте имя, тег или digest."
        )
    if "no space" in text or "disk" in text:
        return ToolExecutionError("Недостаточно места на диске для сканирования.")
    if "unsupported" in text and "architecture" in text:
        return ToolExecutionError(
            "Неподдерживаемая архитектура образа. Укажите platform, например linux/amd64."
        )
    if "timeout" in text:
        return ToolTimeoutError(f"Превышено время ожидания {tool}.")
    if "db" in text and "grype" in tool.lower():
        return ToolExecutionError(
            "База Grype недоступна или повреждена. Выполните make update-db."
        )
    suffix = f" (код {returncode})" if returncode is not None else ""
    return ToolExecutionError(f"Ошибка выполнения {tool}{suffix}: {stderr[:500] or 'без деталей'}")

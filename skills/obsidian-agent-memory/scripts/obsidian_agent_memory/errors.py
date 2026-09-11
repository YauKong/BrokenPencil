"""Domain-specific errors for the portable Agent Memory package."""


class AgentMemoryError(Exception):
    """Base class for all Agent Memory errors."""


class ConfigurationError(AgentMemoryError):
    """Raised when local configuration is invalid or unavailable."""


class ValidationError(AgentMemoryError):
    """Raised when a value does not satisfy the memory contract."""


class ContainmentError(ValidationError):
    """Raised when a resolved path would escape its permitted root."""


class ConflictError(AgentMemoryError):
    """Raised when an operation conflicts with current durable state."""


class LockBusyError(ConflictError):
    """Raised when a root write guard is already held."""


class ProjectionDriftError(ConflictError):
    """Raised when a generated projection differs from its expected target."""


class PlanInvalidatedError(ConflictError):
    """Raised when a requested plan is no longer valid."""

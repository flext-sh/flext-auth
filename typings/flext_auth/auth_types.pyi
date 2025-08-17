from flext_core import TEntityId

__all__ = [
    "TAuditEventType",
    "TAuthResult",
    "TEmail",
    "TLoginAttempt",
    "TPassword",
    "TSecurityContext",
    "TSessionId",
    "TUserId",
    "TUserRole",
    "TUsername",
]

type TUserId = TEntityId
type TSessionId = TEntityId
type TUsername = str
type TEmail = str
type TPassword = str
type TUserRole = str
type TAuthResult = dict[str, object]
type TSecurityContext = dict[str, object]
type TLoginAttempt = dict[str, object]
type TAuditEventType = str

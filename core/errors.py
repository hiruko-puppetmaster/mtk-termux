"""Typed exceptions used across the toolkit."""

from __future__ import annotations


class MtkError(Exception):
    """Base class for all toolkit errors."""


class TransportError(MtkError):
    """USB or byte transport failure."""


class PermissionDenied(TransportError):
    """The process cannot open the USB device or a required path."""


class ProtocolError(MtkError):
    """A wire-level protocol invariant was violated."""


class HandshakeError(ProtocolError):
    """The BROM/Preloader synchronization handshake failed."""


class AuthError(ProtocolError):
    """Authentication, SLA, DAA or certificate handling failed."""


class ExploitError(MtkError):
    """An exploit could not be prepared or executed."""


class ExploitNotSupported(ExploitError):
    """The selected exploit has no complete profile/payload for this SoC."""


class DaError(MtkError):
    """Download Agent loading or booting failed."""


class ParserError(MtkError):
    """Scatter, GPT or DA container parsing failed."""


class RpmbError(MtkError):
    """RPMB request, authentication or provisioning failed."""

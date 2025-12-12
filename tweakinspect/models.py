from __future__ import annotations
from dataclasses import dataclass
from typing import Any


@dataclass
class FunctionTarget:

    target_function_address: int | None
    target_function_name: str | None

    @property
    def name(self) -> str:
        if self.target_function_name:
            return self.target_function_name
        elif self.target_function_address:
            return hex(self.target_function_address)
        return "unknown"

    @property
    def as_logos(self) -> str:
        return f"%hookf {self.name}()"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.__class__.__name__,
            "target_function_address": self.target_function_address,
            "target_function_name": self.target_function_name,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FunctionTarget":
        type_ = data.pop("type")
        if type_ == "ObjectiveCTarget":
            return ObjectiveCTarget.from_dict(data)
        elif type_ == "NewObjectiveCMethodTarget":
            return NewObjectiveCMethodTarget.from_dict(data)
        elif type_ == "FunctionTarget":
            return cls(**data)

        raise ValueError(f"Unknown type: {type_}")


@dataclass
class ObjectiveCTarget(FunctionTarget):

    class_name: str
    method_name: str

    def __init__(self, class_name: str, method_name: str) -> None:
        super().__init__(target_function_address=None, target_function_name=None)
        self.class_name = class_name
        self.method_name = method_name

    @property
    def name(self) -> str:
        return f"-[{self.class_name} {self.method_name}]"

    @property
    def as_logos(self) -> str:
        return f"%hook {self.name}"

    def __hash__(self) -> int:
        return hash(self.name)

    def __eq__(self, other: object) -> bool:
        return str(self) == str(other)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.__class__.__name__,
            "class_name": self.class_name,
            "method_name": self.method_name,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ObjectiveCTarget":
        return cls(**data)


@dataclass
class NewObjectiveCMethodTarget(ObjectiveCTarget):
    class_name: str
    method_name: str

    def __init__(self, class_name: str, method_name: str) -> None:
        super().__init__(class_name, method_name)

    @property
    def as_logos(self) -> str:
        return f"%new {self.name}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.__class__.__name__,
            "class_name": self.class_name,
            "method_name": self.method_name,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NewObjectiveCMethodTarget":
        return cls(**data)


@dataclass
class Hook:

    # The address or name of the item being hooked
    target: FunctionTarget
    # The address of the replacement function
    replacement_address: int

    # The address of the original implementation of the hooked item
    original_address: int

    # The address where the hook is performed
    callsite_address: int

    def __str__(self) -> str:
        return self.target.as_logos

    def __hash__(self) -> int:
        return hash(str(self))

    def __lt__(self, other: object) -> bool:
        return str(self) < str(other)

    def __eq__(self, other: object) -> bool:
        return str(self) == str(other)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.__class__.__name__,
            "target": self.target.to_dict(),
            "replacement_address": self.replacement_address,
            "original_address": self.original_address,
            "callsite_address": self.callsite_address,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Hook":
        return cls(
            target=FunctionTarget.from_dict(data["target"]),
            replacement_address=data["replacement_address"],
            original_address=data["original_address"],
            callsite_address=data["callsite_address"],
        )

def helper(value: str) -> str:
    return value.upper()


class Greeter:
    def greet(self, name: str) -> str:
        return helper(name)

"""Centralized LLM client abstraction for structured outputs.

Supports OpenAI and Anthropic with automatic Pydantic model serialization.
Enables mock LLM responses for testing.
"""

import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class LLMClientError(Exception):
    """Base exception for LLM client errors."""

    pass


class LLMOutputParseError(LLMClientError):
    """Raised when LLM output cannot be parsed into Pydantic model."""

    pass


class LLMProvider(ABC, Generic[T]):
    """Abstract base for LLM providers."""

    @abstractmethod
    async def invoke(
        self,
        prompt: str,
        output_model: type[T],
        temperature: float = 0.3,
        max_tokens: int = 2000,
    ) -> T:
        """Invoke LLM and parse response into Pydantic model.

        Args:
            prompt: Full prompt including instructions and input
            output_model: Pydantic model class to parse response into
            temperature: LLM temperature (0.0-1.0)
            max_tokens: Maximum tokens in response

        Returns:
            Parsed Pydantic model instance

        Raises:
            LLMOutputParseError: If response cannot be parsed
        """
        pass


class MockLLMProvider(LLMProvider[T]):
    """Mock LLM provider for testing.

    Returns provided response directly without actual LLM call.
    Used for deterministic unit testing.
    """

    def __init__(self, response: BaseModel | None = None):
        """Initialize with optional pre-configured response.

        Args:
            response: Pydantic model to return (for deterministic tests)
        """
        self.response = response

    async def invoke(
        self,
        prompt: str,
        output_model: type[T],
        temperature: float = 0.3,
        max_tokens: int = 2000,
    ) -> T:
        """Return pre-configured mock response."""
        if self.response is None:
            raise LLMOutputParseError("MockLLMProvider has no response configured")
        if not isinstance(self.response, output_model):
            raise LLMOutputParseError(
                f"Mock response type {type(self.response)} "
                f"does not match expected {output_model}"
            )
        return self.response


class OpenAILLMProvider(LLMProvider[T]):
    """OpenAI API provider using function calling for structured output."""

    def __init__(self, api_key: str, model: str = "gpt-4-turbo"):
        """Initialize OpenAI provider.

        Args:
            api_key: OpenAI API key
            model: Model name (e.g., gpt-4-turbo, gpt-3.5-turbo)
        """
        self.api_key = api_key
        self.model = model
        try:
            import openai

            self.client = openai.AsyncOpenAI(api_key=api_key)
        except ImportError:
            raise LLMClientError("openai package not installed. Install with: pip install openai")

    async def invoke(
        self,
        prompt: str,
        output_model: type[T],
        temperature: float = 0.3,
        max_tokens: int = 2000,
    ) -> T:
        """Invoke OpenAI API with structured output."""
        try:
            import openai
            from pydantic import TypeAdapter

            # Build JSON schema from Pydantic model
            schema = TypeAdapter(output_model).json_schema()

            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=max_tokens,
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": output_model.__name__,
                        "schema": schema,
                        "strict": False,
                    },
                },
            )

            # Extract JSON from response
            response_text = response.choices[0].message.content
            if not response_text:
                raise LLMOutputParseError("OpenAI returned empty response")

            # Parse JSON and validate with Pydantic
            response_json = json.loads(response_text)
            return output_model(**response_json)

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse OpenAI JSON response: {e}")
            raise LLMOutputParseError(f"Invalid JSON from OpenAI: {e}")
        except ValidationError as e:
            logger.error(f"Pydantic validation failed: {e}")
            raise LLMOutputParseError(f"OpenAI response invalid for {output_model.__name__}: {e}")
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            raise LLMClientError(f"OpenAI API error: {e}")


class AnthropicLLMProvider(LLMProvider[T]):
    """Anthropic Claude API provider."""

    def __init__(self, api_key: str, model: str = "claude-3-sonnet-20240229"):
        """Initialize Anthropic provider.

        Args:
            api_key: Anthropic API key
            model: Model name (e.g., claude-3-opus, claude-3-sonnet)
        """
        self.api_key = api_key
        self.model = model
        try:
            import anthropic

            self.client = anthropic.Anthropic(api_key=api_key)
        except ImportError:
            raise LLMClientError(
                "anthropic package not installed. Install with: pip install anthropic"
            )

    async def invoke(
        self,
        prompt: str,
        output_model: type[T],
        temperature: float = 0.3,
        max_tokens: int = 2000,
    ) -> T:
        """Invoke Anthropic API with structured output."""
        try:
            import anthropic
            from pydantic import TypeAdapter

            # Build JSON schema from Pydantic model
            schema = TypeAdapter(output_model).json_schema()

            response = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                messages=[
                    {
                        "role": "user",
                        "content": f"{prompt}\n\nRespond with valid JSON only, conforming to this schema: {json.dumps(schema)}",
                    }
                ],
            )

            # Extract text from response
            response_text = response.content[0].text
            if not response_text:
                raise LLMOutputParseError("Anthropic returned empty response")

            # Try to extract JSON from response (may be wrapped in markdown)
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0]
            elif "```" in response_text:
                response_text = response_text.split("```")[1].split("```")[0]

            response_json = json.loads(response_text)
            return output_model(**response_json)

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Anthropic JSON response: {e}")
            raise LLMOutputParseError(f"Invalid JSON from Anthropic: {e}")
        except ValidationError as e:
            logger.error(f"Pydantic validation failed: {e}")
            raise LLMOutputParseError(f"Anthropic response invalid for {output_model.__name__}: {e}")
        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            raise LLMClientError(f"Anthropic API error: {e}")


class LLMClient:
    """Unified LLM client wrapper supporting multiple providers."""

    def __init__(self, provider: LLMProvider | None = None):
        """Initialize with specific provider or auto-detect from config.

        Args:
            provider: LLMProvider instance (mock, openai, anthropic, etc.)
                     If None, uses MockLLMProvider
        """
        self.provider = provider or MockLLMProvider()

    async def invoke(
        self,
        prompt: str,
        output_model: type[T],
        temperature: float = 0.3,
        max_tokens: int = 2000,
    ) -> T:
        """Invoke LLM and return parsed Pydantic model.

        Args:
            prompt: Full prompt text
            output_model: Pydantic model to parse into
            temperature: LLM temperature (0.0-1.0, default 0.3 for deterministic)
            max_tokens: Max response tokens

        Returns:
            Pydantic model instance

        Raises:
            LLMClientError: On any LLM error
        """
        return await self.provider.invoke(prompt, output_model, temperature, max_tokens)

    @classmethod
    def from_config(cls, config: "Settings") -> "LLMClient":  # noqa: F821
        """Create LLMClient from application settings.

        Args:
            config: Settings object with LLM configuration

        Returns:
            Configured LLMClient instance
        """
        # For now, return mock. Will be updated when config has LLM settings
        return cls(provider=MockLLMProvider())

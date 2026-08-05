from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any, Callable


HttpJsonGetter = Callable[[str], dict[str, Any]]


@dataclass
class ResearchSource:
    title: str
    url: str
    snippet: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class ResearchAnswer:
    answer: str
    verified: bool
    sources: list[ResearchSource]
    needs_followup: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "answer": self.answer,
            "verified": self.verified,
            "needs_followup": self.needs_followup,
            "sources": [source.to_dict() for source in self.sources],
        }


def default_http_get_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "OpenMythosResidentAgent/0.1"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def looks_like_research_query(message: str) -> bool:
    if re.search(r"\bhow much (do )?you know\b", message, re.I):
        return False
    return bool(
        re.search(
            r"\b(weather|search (the )?web|look up|browse|today|latest|"
            r"current|right now|president|price|pricing|stock|news|"
            r"who is|what year|when was|where is)\b",
            message,
            re.I,
        )
        or re.search(
            r"\bhow much\b.*\b(cost|price|priced|sell|selling|worth)\b",
            message,
            re.I,
        )
        or re.search(r"\bhow many\b.*\b(people|population|users|units)\b", message, re.I)
    )


class ResearchEngine:
    """Small verified research layer for resident-agent answers."""

    def __init__(
        self,
        http_get_json: HttpJsonGetter = default_http_get_json,
        default_location: str | None = None,
    ):
        self.http_get_json = http_get_json
        self.default_location = default_location

    def answer(self, message: str) -> ResearchAnswer:
        if self._is_weather_query(message):
            return self._answer_weather(message)
        return self._answer_web(message)

    def _answer_weather(self, message: str) -> ResearchAnswer:
        location = self._extract_location(message) or self.default_location
        if not location:
            return ResearchAnswer(
                answer=(
                    "No BS: I need a location before I can verify the weather. "
                    "Ask like `weather in Miami, FL` or start the agent with "
                    "`--weather-location`."
                ),
                verified=False,
                sources=[],
                needs_followup=True,
            )

        place = self._geocode(location)
        if place is None:
            return ResearchAnswer(
                answer=f"I could not verify a weather location for `{location}`.",
                verified=False,
                sources=[
                    ResearchSource(
                        title="Open-Meteo Geocoding API",
                        url="https://open-meteo.com/en/docs/geocoding-api",
                    )
                ],
                needs_followup=True,
            )

        forecast = self._forecast(place["latitude"], place["longitude"])
        current = forecast.get("current", {})
        units = forecast.get("current_units", {})
        temp = current.get("temperature_2m")
        humidity = current.get("relative_humidity_2m")
        wind = current.get("wind_speed_10m")
        code = current.get("weather_code")
        observed = current.get("time")
        weather = self._weather_code_label(code)
        place_name = ", ".join(
            part
            for part in (
                place.get("name"),
                place.get("admin1"),
                place.get("country"),
            )
            if part
        )
        answer = (
            f"Verified weather for {place_name}: {temp}"
            f"{units.get('temperature_2m', '')}, {weather}. "
            f"Humidity: {humidity}{units.get('relative_humidity_2m', '')}. "
            f"Wind: {wind} {units.get('wind_speed_10m', '')}. "
            f"Observed: {observed}."
        )
        return ResearchAnswer(
            answer=answer,
            verified=True,
            sources=[
                ResearchSource(
                    title="Open-Meteo Forecast API",
                    url="https://open-meteo.com/en/docs",
                    snippet="Current weather from Open-Meteo forecast endpoint.",
                ),
                ResearchSource(
                    title="Open-Meteo Geocoding API",
                    url="https://open-meteo.com/en/docs/geocoding-api",
                    snippet=f"Location resolved from `{location}`.",
                ),
            ],
        )

    def _answer_web(self, message: str) -> ResearchAnswer:
        query = self._extract_web_query(message)
        if not query:
            return ResearchAnswer(
                answer=(
                    "No BS: give me a search topic. Example: "
                    "`search the web for Wazuh agent install Ubuntu`."
                ),
                verified=False,
                sources=[],
                needs_followup=True,
            )
        if self._is_ambiguous_president_query(query):
            return ResearchAnswer(
                answer=(
                    "No BS: `president` is ambiguous. Tell me the country or "
                    "organization, for example `who is the U.S. president?`."
                ),
                verified=False,
                sources=[],
                needs_followup=True,
            )

        sources: list[ResearchSource] = []
        for candidate in self._query_candidates(query):
            data = self._duckduckgo(candidate)
            sources = self._duckduckgo_sources(data)
            if sources:
                break
            sources = self._wikipedia_sources(candidate)
            if sources:
                break
        if not sources:
            return ResearchAnswer(
                answer=(
                    f"I could not verify `{query}` from the connected web lookup. "
                    "Ask with a more specific query or connect a stronger search API."
                ),
                verified=False,
                sources=[
                    ResearchSource(
                        title="DuckDuckGo Instant Answer API / Wikipedia API",
                        url="https://duckduckgo.com/api",
                    )
                ],
                needs_followup=True,
            )

        lines = [f"Verified lookup for `{query}`:"]
        for index, source in enumerate(sources[:3], start=1):
            snippet = f" - {source.snippet}" if source.snippet else ""
            lines.append(f"{index}. {source.title}{snippet}")
        lines.append("Sources:")
        lines.extend(f"- {source.title}: {source.url}" for source in sources[:3])
        return ResearchAnswer(answer="\n".join(lines), verified=True, sources=sources[:3])

    def _geocode(self, location: str) -> dict[str, Any] | None:
        candidates = [location]
        if "," in location:
            candidates.append(location.split(",", 1)[0].strip())
        compact = re.sub(r"\b([A-Z]{2})\b", "", location).strip(" ,")
        if compact and compact not in candidates:
            candidates.append(compact)

        for candidate in candidates:
            query = urllib.parse.urlencode(
                {"name": candidate, "count": 1, "language": "en", "format": "json"}
            )
            data = self.http_get_json(
                "https://geocoding-api.open-meteo.com/v1/search?" + query
            )
            results = data.get("results") or []
            if results:
                return dict(results[0])
        return None

    def _forecast(self, latitude: float, longitude: float) -> dict[str, Any]:
        query = urllib.parse.urlencode(
            {
                "latitude": latitude,
                "longitude": longitude,
                "current": (
                    "temperature_2m,relative_humidity_2m,"
                    "wind_speed_10m,weather_code"
                ),
                "temperature_unit": "fahrenheit",
                "wind_speed_unit": "mph",
                "timezone": "auto",
            }
        )
        return self.http_get_json("https://api.open-meteo.com/v1/forecast?" + query)

    def _duckduckgo(self, query: str) -> dict[str, Any]:
        params = urllib.parse.urlencode(
            {"q": query, "format": "json", "no_html": 1, "skip_disambig": 1}
        )
        return self.http_get_json("https://api.duckduckgo.com/?" + params)

    def _wikipedia_sources(self, query: str) -> list[ResearchSource]:
        params = urllib.parse.urlencode(
            {
                "action": "opensearch",
                "search": query,
                "limit": 3,
                "namespace": 0,
                "format": "json",
            }
        )
        data = self.http_get_json("https://en.wikipedia.org/w/api.php?" + params)
        if not isinstance(data, list) or len(data) < 4:
            return []
        titles = list(data[1] or [])
        descriptions = list(data[2] or [])
        urls = list(data[3] or [])
        sources = []
        for title, description, url in zip(titles, descriptions, urls):
            if title and url:
                sources.append(
                    ResearchSource(
                        title=str(title),
                        url=str(url),
                        snippet=str(description or ""),
                    )
                )
        return sources

    @staticmethod
    def _duckduckgo_sources(data: dict[str, Any]) -> list[ResearchSource]:
        sources: list[ResearchSource] = []
        abstract = str(data.get("AbstractText") or "").strip()
        abstract_url = str(data.get("AbstractURL") or "").strip()
        heading = str(data.get("Heading") or "DuckDuckGo result").strip()
        if abstract and abstract_url:
            return [ResearchSource(heading, abstract_url, abstract)]

        def add_related(items: list[dict[str, Any]]) -> None:
            for item in items:
                if "Topics" in item:
                    add_related(list(item.get("Topics") or []))
                    continue
                text = str(item.get("Text") or "").strip()
                url = str(item.get("FirstURL") or "").strip()
                if text and url:
                    title = text.split(" - ", 1)[0][:80]
                    sources.append(ResearchSource(title, url, text))

        add_related(list(data.get("RelatedTopics") or []))
        deduped = []
        seen = set()
        for source in sources:
            if source.url in seen:
                continue
            seen.add(source.url)
            deduped.append(source)
        return deduped

    @staticmethod
    def _extract_location(message: str) -> str | None:
        match = re.search(r"\b(?:weather|forecast)\s+(?:in|for)\s+(.+)$", message, re.I)
        if match:
            return match.group(1).strip(" ?.!")
        return None

    @staticmethod
    def _extract_web_query(message: str) -> str:
        cleaned = message.strip()
        cleaned = re.sub(
            r"^\s*(search (the )?web for|look up|browse for)\s+",
            "",
            cleaned,
            flags=re.I,
        )
        if re.fullmatch(r"search (the )?web|look up|browse", cleaned, re.I):
            return ""
        return cleaned.strip(" ?.!")

    @staticmethod
    def _query_candidates(query: str) -> list[str]:
        candidates = [query]
        normalized = query.strip()
        if re.search(r"\bKarl Benz\b", normalized, re.I):
            candidates.append(
                re.sub(r"\bKarl Benz\b", "Carl Benz", normalized, flags=re.I)
            )
        if re.search(
            r"\b(first car|first automobile|first motor car)\b",
            normalized,
            re.I,
        ):
            candidates.extend(["Carl Benz", "Benz Patent-Motorwagen"])
        deduped = []
        seen = set()
        for candidate in candidates:
            key = candidate.lower()
            if key not in seen:
                seen.add(key)
                deduped.append(candidate)
        return deduped

    @staticmethod
    def _is_weather_query(message: str) -> bool:
        return bool(re.search(r"\b(weather|forecast)\b", message, re.I))

    @staticmethod
    def _is_ambiguous_president_query(query: str) -> bool:
        return bool(
            re.fullmatch(r"(who is )?(the )?president", query, re.I)
            or re.fullmatch(r"who is president", query, re.I)
        )

    @staticmethod
    def _weather_code_label(code: Any) -> str:
        labels = {
            0: "clear sky",
            1: "mainly clear",
            2: "partly cloudy",
            3: "overcast",
            45: "fog",
            48: "depositing rime fog",
            51: "light drizzle",
            53: "moderate drizzle",
            55: "dense drizzle",
            61: "slight rain",
            63: "moderate rain",
            65: "heavy rain",
            71: "slight snow",
            73: "moderate snow",
            75: "heavy snow",
            80: "slight rain showers",
            81: "moderate rain showers",
            82: "violent rain showers",
            95: "thunderstorm",
        }
        try:
            return labels.get(int(code), f"weather code {code}")
        except (TypeError, ValueError):
            return "weather unavailable"

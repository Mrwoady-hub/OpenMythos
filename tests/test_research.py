from open_mythos.research import ResearchEngine, looks_like_research_query


def test_weather_research_uses_open_meteo_sources():
    calls = []

    def fake_get_json(url):
        calls.append(url)
        if "geocoding-api.open-meteo.com" in url:
            return {
                "results": [
                    {
                        "name": "Miami",
                        "admin1": "Florida",
                        "country": "United States",
                        "latitude": 25.7743,
                        "longitude": -80.1937,
                    }
                ]
            }
        return {
            "current": {
                "temperature_2m": 82.4,
                "relative_humidity_2m": 65,
                "wind_speed_10m": 8.1,
                "weather_code": 2,
                "time": "2026-05-26T14:00",
            },
            "current_units": {
                "temperature_2m": "°F",
                "relative_humidity_2m": "%",
                "wind_speed_10m": "mph",
            },
        }

    engine = ResearchEngine(http_get_json=fake_get_json)
    answer = engine.answer("weather in Miami, FL")

    assert answer.verified is True
    assert "Miami, Florida, United States" in answer.answer
    assert "82.4°F" in answer.answer
    assert answer.sources[0].url == "https://open-meteo.com/en/docs"
    assert any("temperature_unit=fahrenheit" in call for call in calls)


def test_weather_geocoding_retries_city_when_region_query_fails():
    calls = []

    def fake_get_json(url):
        calls.append(url)
        if "geocoding-api.open-meteo.com" in url and "Miami%2C+FL" in url:
            return {"results": []}
        if "geocoding-api.open-meteo.com" in url and "Miami" in url:
            return {
                "results": [
                    {
                        "name": "Miami",
                        "admin1": "Florida",
                        "country": "United States",
                        "latitude": 25.7743,
                        "longitude": -80.1937,
                    }
                ]
            }
        return {
            "current": {
                "temperature_2m": 80,
                "relative_humidity_2m": 60,
                "wind_speed_10m": 5,
                "weather_code": 0,
                "time": "2026-05-26T14:00",
            },
            "current_units": {
                "temperature_2m": "°F",
                "relative_humidity_2m": "%",
                "wind_speed_10m": "mph",
            },
        }

    engine = ResearchEngine(http_get_json=fake_get_json)
    answer = engine.answer("weather in Miami, FL")

    assert answer.verified is True
    assert len([call for call in calls if "geocoding-api" in call]) == 2


def test_weather_research_requires_location_when_default_missing():
    engine = ResearchEngine(http_get_json=lambda url: {})

    answer = engine.answer("whats the weather")

    assert answer.verified is False
    assert answer.needs_followup is True
    assert "need a location" in answer.answer


def test_web_research_returns_cited_duckduckgo_result():
    def fake_get_json(url):
        assert "api.duckduckgo.com" in url
        return {
            "Heading": "Karl Benz",
            "AbstractText": "Karl Benz patented the Benz Patent-Motorwagen in 1886.",
            "AbstractURL": "https://en.wikipedia.org/wiki/Carl_Benz",
            "RelatedTopics": [],
        }

    engine = ResearchEngine(http_get_json=fake_get_json)
    answer = engine.answer("look up what year was the first car built")

    assert answer.verified is True
    assert "Karl Benz" in answer.answer
    assert "Sources:" in answer.answer
    assert answer.sources[0].url == "https://en.wikipedia.org/wiki/Carl_Benz"


def test_web_research_falls_back_to_wikipedia_when_duckduckgo_is_empty():
    calls = []

    def fake_get_json(url):
        calls.append(url)
        if "api.duckduckgo.com" in url:
            return {}
        assert "en.wikipedia.org" in url
        return [
            "Karl Benz first automobile",
            ["Carl Benz"],
            ["German inventor, patented the Benz Patent-Motorwagen."],
            ["https://en.wikipedia.org/wiki/Carl_Benz"],
        ]

    engine = ResearchEngine(http_get_json=fake_get_json)
    answer = engine.answer("look up Karl Benz first automobile")

    assert answer.verified is True
    assert answer.sources[0].title == "Carl Benz"
    assert "https://en.wikipedia.org/wiki/Carl_Benz" in answer.answer
    assert any("api.duckduckgo.com" in call for call in calls)
    assert any("en.wikipedia.org" in call for call in calls)


def test_web_research_uses_query_fallback_for_first_car_wording():
    searched = []

    def fake_get_json(url):
        searched.append(url)
        if "api.duckduckgo.com" in url:
            return {}
        if "Carl+Benz" in url:
            return [
                "Carl Benz",
                ["Carl Benz"],
                ["German inventor, patented the Benz Patent-Motorwagen."],
                ["https://en.wikipedia.org/wiki/Carl_Benz"],
            ]
        return ["first car", [], [], []]

    engine = ResearchEngine(http_get_json=fake_get_json)
    query = "what year was the first car built"
    answer = engine.answer(query)

    assert looks_like_research_query(query)
    assert answer.verified is True
    assert answer.sources[0].title == "Carl Benz"
    assert any("Carl+Benz" in call for call in searched)


def test_how_much_you_know_is_not_research_query():
    assert not looks_like_research_query("how much you know and need to learn")
    assert looks_like_research_query("how much does this SSD cost")


def test_web_research_rejects_ambiguous_president_question():
    engine = ResearchEngine(http_get_json=lambda url: {})

    answer = engine.answer("who is the president")

    assert answer.verified is False
    assert answer.needs_followup is True
    assert "ambiguous" in answer.answer

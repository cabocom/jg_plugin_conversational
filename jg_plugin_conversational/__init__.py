"""Paquete jg_plugin_conversational: Plugin conversacional oficial para jg_agente.

Proporciona herramientas y motores de diálogo en lenguaje natural
(clima determinista/Azure Maps y noticias RSS oficiales) completamente
desacoplados del core del agente.
"""

from jg_plugin_conversational.news import NewsArgs, create_news_tool, get_news_fn
from jg_plugin_conversational.plugin import PLUGIN_CLASS, ConversationalPlugin
from jg_plugin_conversational.weather import WeatherArgs, create_weather_tool, get_weather_fn

__version__ = "1.0.0"

__all__ = [
    "PLUGIN_CLASS",
    "ConversationalPlugin",
    "NewsArgs",
    "WeatherArgs",
    "__version__",
    "create_news_tool",
    "create_weather_tool",
    "get_news_fn",
    "get_weather_fn",
]

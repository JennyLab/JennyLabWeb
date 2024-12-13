---
layout: default
title: "Bienvenido a JennyLab"
---

# Bienvenido a JennyLab

Aquí encontrarás ejemplos y tutoriales sobre diversas áreas.

## Últimos Posts:
<ul>
  {% for page in site.pages limit:5 %}
    <li><a href="{{ page.url }}">{{ page.title }}</a></li>
  {% endfor %}
</ul> 
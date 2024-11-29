---
layout: default
title: "Bienvenido a JennyLab"
---

# Bienvenido a JennyLab

Aquí encontrarás ejemplos y tutoriales sobre diversas áreas.

## Últimos Posts:
<ul>
  {% for post in site.posts limit:5 %}
    <li><a href="{{ post.url }}">{{ post.title }}</a></li>
  {% endfor %}
</ul> 
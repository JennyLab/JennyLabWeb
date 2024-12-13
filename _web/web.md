
layout: default
title: "Todos los Posts"
permalink: /web/
---

# Lista de Posts

<ul>
  {% for post in site.web %}
    <li>
      <a href="{{ post.url }}">{{ post.title }}</a>
      <span>{{ post.date | date: "%d %b %Y" }}</span>
    </li>
  {% endfor %}
</ul>

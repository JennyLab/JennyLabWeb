---
layout: default
title: "Mis Posts"
---

<h2>Últimos Posts</h2>
<ul>
  {% for post in site.posts %}
    <li><a href="{{ post.url }}">{{ post.title }}</a></li>
  {% endfor %}
</ul>

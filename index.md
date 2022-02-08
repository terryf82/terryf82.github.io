---
title:  "CyberSec Writeups"
---

## Recent Writeups:

<ul>
  {% for post in site.posts %}
    <li>
      <a href="{{ post.url }}">{{ post.title }}</a>
      <p>{{ post.date | date_to_string }}</p>
      {% if post.summary %}
        {{ post.summary }}
      {% else %}
        {{ post.excerpt }}
      {% endif %}
      <p>
      {% if post.tags %}
        <span class='tag'>{{ post.tags | join: "</span> <span class='tag'>" }}</span>
      {% endif %}
      </p>
    </li>
  {% endfor %}
</ul>

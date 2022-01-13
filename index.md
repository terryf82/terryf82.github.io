---
title:  "CyberSec Writeups"
---

## Recent Writeups:

<ul>
  {% for post in site.posts %}
    <li>
      <a href="{{ post.url }}">{{ post.title }}</a>
      <p>
      {% if post.tags %}
        <span class='tag'>{{ post.tags | join: "</span> <span class='tag'>" }}</span>
      {% endif %}
      </p>
      {{ post.excerpt }}
    </li>
  {% endfor %}
</ul>

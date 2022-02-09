---
title:  "CyberSec Writeups"
---

## Recent Writeups:

<div>
  {% for post in site.posts %}
    <div style="display:flex; margin-bottom:2em">
      <div style="flex:0.25; margin-right:1em">
        <img src="/assets/images/{{ post.name }}/main.png" >
      </div>
      <div style="flex:0.75">
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
      </div>
    </div>
  {% endfor %}
</div>
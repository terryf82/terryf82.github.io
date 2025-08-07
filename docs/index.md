---
hide:
  - toc
---

# pitfallen.net

### (`pit·fawl·en`) *`[adj]`*: *educated in the art of making things work, through the full enumeration of all possible routes destined to fail.*

---

## Recent Posts
{% for post in get_blog_posts() %}
### [{{ post.title }}](/{{ post.url }})
{{ post.date_obj }}

*{{ post.summary }}*

---
{% endfor %}
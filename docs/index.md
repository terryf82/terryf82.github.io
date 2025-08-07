---
hide:
  - toc
---

# pitfallen.net

### (`pit·fawl·en`) *`[adj]`*: *educated in the ways of making things work through the full enumeration of all routes leading to failure.*

---

## New Posts
{% for post in get_blog_posts() %}
### [{{ post.title }}](/{{ post.url }})
{{ post.date_obj }}

*{{ post.summary }}*

---
{% endfor %}
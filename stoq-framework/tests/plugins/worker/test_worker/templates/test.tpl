{% block title %}*Test Results*{% endblock %}
{%block body %}

{% for result in results["results"] %}
*md5:* {{ result["md5"] }}
*sha1:* {{ result["sha1"] }}
*sha256:* {{ result["sha256"] }}
*sha512:* {{ result["sha512"] }}
*str:* {{ result["scan"]["str"] }}
*int:* {{ result["scan"]["int"] }}
{% endfor %}
{% endblock %}

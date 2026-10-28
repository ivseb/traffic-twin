"""Spec knobs of the reference generator (sanitizer revision 1.1).

Revision 1.1 settled most of the v1.0 ambiguities (see conformance/AMBIGUITIES.md).
What remains here are the constants of the spec and the readings the conformance
agent chose where the 1.1 text still allows more than one answer, so that a spec
patch is a one-line change followed by `python3 conformance/ref/gen_vectors.py`.
"""

# 0.3: (inclusive upper bound, class); None = no bound.
LEN_CLASSES = [(8, 'l8'), (32, 'l32'), (128, 'l128'), (1024, 'l1024'), (None, 'lmax')]

NAME_LIMIT = 64            # 8.1.4: distinct output names for headers, cookies, query, form
MAX_PATH_SEGMENTS = 32     # 4.1.4
AUTO_WORD_MAX_BYTES = 40   # 4.2.5
MODE_MAX_SECONDS = 7 * 86400  # 4.3 and 15: auto_words and discovery end 7 days after created_at
LEXEME_MAX_BYTES = 64      # 5.3
EXPONENT_MAX = 9999        # 5.3
SUBJECT_MAX_BYTES = 8192   # 11.1
EVENT_MAX_BYTES = 524288   # 10.3
DISC_MAX_PATHS = 4096      # 15

# A-EVENT-SIZE-BASE: 10.3 measures the complete event, whose source-filled fields differ
# between sources. The reference measures the sanitizer output and the generator keeps
# every vector at least this far from the limit, so the base does not change the result.
EVENT_SIZE_MARGIN = 4096

# A-HDR-COLLAPSED-RULE: a joined {*} header value uses the rule of its original name only
# when all the joined values came from the same original name.
COLLAPSED_HEADER_RULE_SINGLE_NAME = True

# A-NOEQ-DISC: query and form parts without "=" always receive drop, but no explicit rule
# applies to them, so in discovery mode they still add a req.query.{*} / req.body.* entry.
NOEQ_PARTS_IN_DISCOVERY = True

# A-CONTAINER-KEEP: keep/hmac/bucket rules on containers are "always ignored", also when
# choosing the group of a container drop (they do not shadow a weaker drop).
CONTAINER_NON_DROP_SHADOWS = False

# A-PATH-TIME: 4.2.4 "lo stesso vale per il valore originale da cui nasce un time:" read as:
# bucket(time) on a path parameter applies only if the decoded segment matches the keep grammar.
PATH_TIME_NEEDS_SAFE_VALUE = True

# A-FORM-TRUNC: a form body is a name map like the query, so its {trunc} is an array.
FORM_TRUNC_AS_ARRAY = True

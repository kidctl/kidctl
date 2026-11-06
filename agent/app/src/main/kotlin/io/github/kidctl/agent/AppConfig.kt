package io.github.kidctl.agent

/**
 * A managed-configuration key an app declares (its `res/xml` app
 * restrictions, read with RestrictionsManager.getManifestRestrictions), in a
 * form the unit tests can build without Android.
 */
data class Declared(val key: String, val type: Type, val choices: List<String> = emptyList()) {
    /** RestrictionEntry.TYPE_*; HIDDEN is TYPE_NULL (restrictionType "hidden": a string not shown to users). */
    enum class Type(val xml: String) {
        BOOLEAN("bool"), INTEGER("integer"), STRING("string"), HIDDEN("hidden"), CHOICE("choice"),
        MULTI_SELECT("multi-select"), BUNDLE("bundle"), BUNDLE_ARRAY("bundle_array"),
    }
}

/**
 * device.app_config of one package, made ready for setApplicationRestrictions:
 * each policy value (Boolean, Int/Long, String or List<String> from the JSON)
 * converted to the type the app declares for its key. Bundle-free: the
 * Enforcer turns [Plan.values] into a Bundle.
 */
object AppConfig {
    /**
     * Values to set (Boolean, Int, String, or Array<String> for a
     * multi-select) and, per key that cannot be set, why. A key the app does
     * not declare, or a value of the wrong type, is left out (the others are
     * still set) and reported.
     */
    class Plan(val values: Map<String, Any>, val problems: Map<String, String>)

    fun plan(declared: List<Declared>, want: Map<String, Any>): Plan {
        val byKey = declared.associateBy { it.key }
        val values = sortedMapOf<String, Any>()
        val problems = sortedMapOf<String, String>()
        for ((k, v) in want) {
            val d = byKey[k]
            if (d == null) {
                val near = declared.firstOrNull { it.key.equals(k, ignoreCase = true) }?.key
                problems[k] = "not declared by the app" + (near?.let { " (did you mean $it?)" } ?: "")
                continue
            }
            when (val c = coerce(d, v)) {
                is Coerced.Ok -> values[k] = c.value
                is Coerced.Bad -> problems[k] = c.why
            }
        }
        return Plan(values, problems)
    }

    sealed class Coerced {
        data class Ok(val value: Any) : Coerced()
        data class Bad(val why: String) : Coerced()
    }

    fun coerce(d: Declared, v: Any): Coerced {
        val secret = secret(d.key)
        fun shown(x: Any) = if (secret) "<redacted>" else when (x) {
            is String -> "\"$x\""
            is List<*> -> x.joinToString(", ", "[", "]")
            else -> x.toString()
        }
        fun kind(x: Any) = when (x) {
            is Boolean -> "a boolean"
            is Int, is Long -> "an integer"
            is String -> "a string"
            is List<*> -> "a list"
            else -> "a ${x.javaClass.simpleName}"
        }
        fun bad(expects: String) = Coerced.Bad("${d.type.xml} restriction expects $expects, got ${kind(v)} ${shown(v)}")
        val scalar: String? = when (v) {
            is String -> v
            is Boolean, is Int, is Long -> v.toString()
            else -> null
        }
        return when (d.type) {
            Declared.Type.BOOLEAN -> when {
                v is Boolean -> Coerced.Ok(v)
                v is String && v.lowercase() in setOf("true", "false") -> Coerced.Ok(v.lowercase() == "true")
                else -> bad("true or false")
            }
            Declared.Type.INTEGER -> {
                val n: Long? = when (v) {
                    is Int -> v.toLong()
                    is Long -> v
                    is String -> v.trim().toLongOrNull()
                    else -> null
                }
                if (n != null && n in Int.MIN_VALUE..Int.MAX_VALUE) Coerced.Ok(n.toInt()) else bad("a 32-bit integer")
            }
            Declared.Type.STRING, Declared.Type.HIDDEN -> scalar?.let { Coerced.Ok(it) } ?: bad("a string")
            Declared.Type.CHOICE -> when {
                scalar == null -> bad("one of ${d.choices}")
                d.choices.isNotEmpty() && scalar !in d.choices ->
                    Coerced.Bad("choice restriction: ${shown(scalar)} is not one of ${d.choices}")
                else -> Coerced.Ok(scalar)
            }
            Declared.Type.MULTI_SELECT -> {
                val list: List<String>? = when (v) {
                    is List<*> -> v.map { it as? String ?: return bad("a list of strings") }
                    else -> scalar?.let { listOf(it) }
                }
                val unknown = list?.filter { d.choices.isNotEmpty() && it !in d.choices }.orEmpty()
                when {
                    list == null -> bad("a list of strings")
                    unknown.isNotEmpty() -> Coerced.Bad("multi-select restriction: ${shown(unknown)} not among ${d.choices}")
                    else -> Coerced.Ok(list.toTypedArray())
                }
            }
            Declared.Type.BUNDLE, Declared.Type.BUNDLE_ARRAY ->
                Coerced.Bad("${d.type.xml} restrictions are not supported by kidctl")
        }
    }

    /** Same keys and values (arrays compared by content). */
    fun same(got: Map<String, Any?>, want: Map<String, Any>): Boolean =
        got.keys == want.keys && want.all { (k, w) ->
            val g = got[k]
            if (w is Array<*>) g is Array<*> && g.contentEquals(w) else g == w
        }

    /** Keys whose value is never shown in events or logs (an auth key, a password...). */
    fun secret(key: String): Boolean = SECRET.containsMatchIn(key)
    private val SECRET = Regex("key|token|secret|passw|credential", RegexOption.IGNORE_CASE)

    /** "A=true, B=[x, y], Name=\"z\"" sorted by key, secret values redacted; "(none)" when empty. */
    fun describe(values: Map<String, Any?>): String {
        if (values.isEmpty()) return "(none)"
        return values.toSortedMap().entries.joinToString(", ") { (k, v) ->
            val s = when {
                secret(k) -> "<redacted>"
                v is String -> "\"$v\""
                v is Array<*> -> v.joinToString(", ", "[", "]")
                else -> v.toString()
            }
            "$k=$s"
        }
    }
}

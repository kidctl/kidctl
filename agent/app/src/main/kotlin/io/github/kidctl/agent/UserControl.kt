package io.github.kidctl.agent

/**
 * device.user_control_disabled: packages whose Force stop and Clear storage /
 * Clear cache buttons Android disables in Settings
 * (DevicePolicyManager.setUserControlDisabledPackages, which replaces the
 * whole list). The agent's own package is always in it: the policy can add
 * packages, never drop the agent's protection.
 */
object UserControl {
    /** The list to set: [own] first, then the policy's packages, each once. */
    fun wanted(own: String, policy: List<String>): List<String> = (listOf(own) + policy).distinct()

    /** Same packages, order aside. */
    fun same(want: List<String>, got: List<String>): Boolean = want.toSet() == got.toSet()

    /** Wanted but not in force (read back). */
    fun missing(want: List<String>, got: List<String>): List<String> = want.filter { it !in got }

    /** In force but no longer wanted (read back). */
    fun extra(want: List<String>, got: List<String>): List<String> = got.filter { it !in want }.distinct()
}

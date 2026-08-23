plugins {
    id("org.jetbrains.intellij.platform")
    kotlin("jvm") version "2.4.0"
}

group = "dev.vetto"
version = "0.0.1"

kotlin {
    jvmToolchain(21)
}

dependencies {
    intellijPlatform {
        intellijIdea("2026.2.0.1")
    }
}

intellijPlatform {
    pluginConfiguration {
        ideaVersion {
            sinceBuild = "262"
        }
    }
}

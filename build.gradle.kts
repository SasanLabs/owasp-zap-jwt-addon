import org.zaproxy.gradle.addon.AddOnPlugin
import org.zaproxy.gradle.addon.AddOnStatus
import org.zaproxy.gradle.addon.misc.ConvertMarkdownToHtml
import org.zaproxy.gradle.addon.misc.CreateGitHubRelease
import org.zaproxy.gradle.addon.misc.ExtractLatestChangesFromChangelog

plugins {
    id("com.diffplug.gradle.spotless") version "3.27.2"
    id("com.github.ben-manes.versions") version "0.28.0"
    `java-library`
    id("org.zaproxy.add-on") version "0.3.0"
}

repositories {
    mavenCentral()
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

spotless {
    java {
        licenseHeaderFile("$rootDir/gradle/spotless/license.java")
        googleJavaFormat().aosp()
    }
}

tasks.withType<JavaCompile>().configureEach { options.encoding = "utf-8" }

version = "1.0.1"
description = "Detect JWT requests and scan them to find related vulnerabilities"

zapAddOn {
    addOnName.set("JWT Support")
    zapVersion.set("2.9.0")
    addOnStatus.set(AddOnStatus.ALPHA)

    manifest {
        author.set("KSASAN preetkaran20@gmail.com")
		repo.set("https://github.com/SasanLabs/owasp-zap-jwt-addon/")
        dependencies {
            addOns {
                register("commonlib")
                register("fuzz") {
    				version.set("13.*")
				}
            }
        }
        changesFile.set(tasks.named<ConvertMarkdownToHtml>("generateManifestChanges").flatMap { it.html })
    }
}

dependencies {
    implementation("org.json:json:20190722")
    // https://mvnrepository.com/artifact/com.nimbusds/nimbus-jose-jwt
    implementation("com.nimbusds:nimbus-jose-jwt:8.3")

    compileOnly("org.zaproxy.addon:commonlib:1.0.0")
    
    // https://mvnrepository.com/artifact/org.zaproxy.addon/fuzz
    compileOnly("org.zaproxy.addon:fuzz:13.0.0")

    testImplementation("org.zaproxy.addon:commonlib:1.0.0")
}

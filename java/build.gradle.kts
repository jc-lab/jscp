plugins {
    id("java-library")
    `maven-publish`
    kotlin("jvm") version Version.KOTLIN
    id("com.google.protobuf") version "0.9.1"
}

group = "kr.jclab.jscp"
version = Version.PROJECT

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
}

tasks.withType<Test> {
    systemProperty("file.encoding", "UTF-8")
}

tasks.withType<Javadoc> {
    options.encoding = "UTF-8"
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.9.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.assertj:assertj-core:3.26.3")
    testImplementation("io.kotlintest:kotlintest-runner-junit5:3.4.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")

    implementation("com.google.protobuf:protobuf-java:${Version.PROTOBUF}")
    implementation("org.bouncycastle:bcprov-jdk18on:${Version.BOUNCY_CASLTE}")
    implementation("org.bouncycastle:bcpkix-jdk18on:${Version.BOUNCY_CASLTE}")
    testImplementation(kotlin("test"))
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:${Version.PROTOBUF}"
    }
}

tasks.test {
    useJUnitPlatform()
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
        }
    }
}

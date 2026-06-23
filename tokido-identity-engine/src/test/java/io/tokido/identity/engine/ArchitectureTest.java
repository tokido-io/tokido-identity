package io.tokido.identity.engine;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

class ArchitectureTest {

    private final JavaClasses core = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("io.tokido.identity");

    @Test
    void core_has_no_framework_imports() {
        noClasses().should().dependOnClassesThat()
                .resideInAnyPackage(
                        "org.springframework..",
                        "io.quarkus..",
                        "jakarta.servlet..",
                        "jakarta.ws.rs..",
                        "javax.servlet..")
                .check(core);
    }

    @Test
    void core_does_not_use_service_loader() {
        noClasses().should().dependOnClassesThat()
                .haveFullyQualifiedName("java.util.ServiceLoader")
                .check(core);
    }
}

package io.tokido.identity;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * The api module is the zero-dependency SPI surface: no framework imports, no
 * Nimbus/JOSE (which lives in the engine), and no reflection/ServiceLoader.
 */
class ApiArchitectureTest {

    private final JavaClasses api = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("io.tokido.identity");

    @Test
    void api_has_no_framework_or_jose_dependencies() {
        noClasses().should().dependOnClassesThat()
                .resideInAnyPackage(
                        "org.springframework..",
                        "io.quarkus..",
                        "jakarta.servlet..",
                        "jakarta.ws.rs..",
                        "javax.servlet..",
                        "com.nimbusds..")
                .check(api);
    }

    @Test
    void api_does_not_use_service_loader() {
        noClasses().should().dependOnClassesThat()
                .haveFullyQualifiedName("java.util.ServiceLoader")
                .check(api);
    }
}

package com.piggymetrics.account.client;

import com.piggymetrics.account.domain.Account;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author cdov
 */
@Disabled("Hystrix fallbacks are not available on Spring Cloud 2021.x, account-service still has to move to Resilience4j")
@ExtendWith(OutputCaptureExtension.class)
@SpringBootTest(properties = {
        "feign.hystrix.enabled=true"
})
public class StatisticsServiceClientFallbackTest {
    @Autowired
    private StatisticsServiceClient statisticsServiceClient;

    @Test
    public void testUpdateStatisticsWithFailFallback(CapturedOutput outputCapture) {
        statisticsServiceClient.updateStatistics("test", new Account());

        assertThat(outputCapture).contains("Error during update statistics for account: test");
    }

}

/***************************************************************************
 * Copyright (C) 2016 Ping Identity Corporation
 * All rights reserved.
 *
 * The contents of this file are the property of Ping Identity Corporation.
 * You may not copy or use this file, in either source code or executable
 * form, except in compliance with terms set by Ping Identity Corporation.
 * For further information please contact:
 *
 *     Ping Identity Corporation
 *     1001 17th Street Suite 100
 *     Denver, CO 80202
 *     303.468.2900
 *     http://www.pingidentity.com
 *
 **************************************************************************/
package com.pingidentity.svc.impl;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

import com.pingidentity.svc.impl.BlackListSvcImpl;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class BlackListSvcImplSanityTest {

    /**
     * Not a __real__ unit test, as it doesn't really assert anything.
     * This is just a sanity check/test to make sure that the BlackList can 
     * handle a decent amount of traffic and to visually check that the topN
     * list looks reasonable.
     */
    @Test
    public void testThreadedSanityCheck() throws InterruptedException {
        log.info("Threaded test started.");
        
        BlackListSvcImpl bl = new BlackListSvcImpl();
        
        int threads = 5;
        int requestsPerThread = 200_000;
        long totalRequests = threads * requestsPerThread;
        int logInterval = 10_000;

        long startTime = System.nanoTime();
        ExecutorService executor = Executors.newFixedThreadPool(threads);

        for (int j = 0; j < threads; j++) {
            executor.execute(() -> {
                for (int i = 0; i < requestsPerThread; i++) {
                    int randomSuffix = (int) Math.ceil(Math.random() * 255);
                    String ip = "10.10.10." + randomSuffix;
                    if (i % logInterval == 0) {
                        log.debug("In request: {} for ip: {}", i, ip);
                    }
                    // track this ip
                    bl.track(ip);
                }
            });
        }

        executor.shutdown();
        executor.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS);

        long endTime = System.nanoTime();
        long totalTime = (endTime - startTime) / 1000000L;
        log.info("{} entries tracked in {} ms", totalRequests, totalTime);
        // just confirm that there are ~totalRequest/256 in the blacklist (~3900)
        log.info("Top 10 offenders: {}", bl.getTopN(10));
    }
}

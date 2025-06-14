import time

from beets.util.rate_limiter import RateLimiter

# 10 reqs per 0.1 second
REQS_PER_INTERVAL = 10
INTERVAL_SEC = 0.1

# Expected time to wait to be able to do one more request after being rate limited
WAIT_FOR_ONE_REQ = INTERVAL_SEC / REQS_PER_INTERVAL


def run_and_collect_delta_start_times(num_reqs: int) -> list[float]:
    """Launch requests through the rate limiter and collect the durations between the
    time before the first request and the starting time of each request.

    :param num_reqs: Number of requests to run
    :return: A list of delta start times in seconds: non rate-limited ones should be
        close to 0
    """
    rate_limiter = RateLimiter(REQS_PER_INTERVAL, INTERVAL_SEC)

    delta_start_times = []

    start = time.time()
    for _ in range(num_reqs):
        with rate_limiter:
            delta_start_times.append(time.time() - start)

    return delta_start_times


def test_all_reqs_in_one_interval():
    delta_start_times = run_and_collect_delta_start_times(REQS_PER_INTERVAL)

    for i in range(10):
        assert delta_start_times[i] < WAIT_FOR_ONE_REQ, (
            f"request {i} should not have been rate-limited"
        )


def test_more_reqs_in_one_interval():
    delta_start_times = run_and_collect_delta_start_times(2 * REQS_PER_INTERVAL)

    # 20 reqs with rate-limitation of 10 reqs per 0.1s
    # -> 10 reqs immediately, then 10*(1 req per 0.1s)

    for i in range(10):
        assert delta_start_times[i] < WAIT_FOR_ONE_REQ, (
            f"request {i} should not have been rate-limited"
        )

    for i in range(10, len(delta_start_times)):
        # Non rate-limited reqs are at interval 0
        # 1st rate-limited req is at interval 1
        # 2nd rate-limited req is at interval 2
        # etc.
        expected_interval = i - 9
        expected_start_time = expected_interval * WAIT_FOR_ONE_REQ

        assert delta_start_times[i] >= expected_start_time, (
            f"request {i} has executed sooner than it should have"
        )
        assert delta_start_times[i] < (
            expected_start_time + WAIT_FOR_ONE_REQ
        ), f"request {i} has executed much later than it should have"


def test_reuse_after_no_requests():
    rate_limiter = RateLimiter(REQS_PER_INTERVAL, INTERVAL_SEC)

    # Use up all requests
    start = time.time()
    for _ in range(REQS_PER_INTERVAL):
        with rate_limiter:
            pass
    end = time.time()
    assert (end - start) < WAIT_FOR_ONE_REQ, (
        "requests should not have been rate-limited"
    )

    # Do no request for half an interval
    time.sleep(INTERVAL_SEC / 2)

    # Now, we should be able to do half the REQS_PER_INTERVAL with no rate limitation
    start = time.time()
    for _ in range(REQS_PER_INTERVAL // 2):
        with rate_limiter:
            pass
    end = time.time()
    assert (end - start) < WAIT_FOR_ONE_REQ, (
        "requests should not have been rate-limited"
    )

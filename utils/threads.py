from threading import Thread, Lock
from queue import Queue


class Worker(Thread):
    """Thread executing tasks from a given tasks queue"""
    lck = Lock()

    def __init__(self, tasks, threadID):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.threadID = threadID
        self.start()

    def run(self):
        while True:
            (func, args, kargs) = self.tasks.get()
            try:
                outcome = func(*args, **kargs)

            except (Exception, IndexError) as e:
                print(e)
            finally:
                self.tasks.task_done()


class ThreadPool:
    """Pool of threads consuming tasks from a queue"""

    def __init__(self, num_threads):
        self.tasks = Queue(num_threads)
        for _ in range(num_threads):
            Worker(self.tasks, _)

    def add_task(self, func, *args, **kargs):
        """Add a task to the queue"""
        self.tasks.put((func, args, kargs))

    def wait_completion(self):
        """Wait for completion of all the tasks in the queue"""
        self.tasks.join()

    def count(self):
        """Return number of tasks in the queue"""
        return self.tasks.qsize()

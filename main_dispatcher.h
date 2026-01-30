#pragma once
#include <functional>
#include <vector>
#include <mutex>

class MainDispatcher {
public:
    static MainDispatcher& instance();
    
    // Worker thread calls this to post tasks to Main Thread
    void queue_task(std::function<void()> task);
    
    // Main thread calls this to execute pending tasks
    void process_pending();

private:
    std::mutex m_mtx;
    std::vector<std::function<void()>> m_queue;
};

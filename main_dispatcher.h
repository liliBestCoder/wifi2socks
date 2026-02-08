#pragma once
#include <functional>
#include <vector>
#include <mutex>
#include <windows.h>

class MainDispatcher {
public:
    static MainDispatcher& instance();
    MainDispatcher();
    ~MainDispatcher();
    
    // Worker thread calls this to post tasks to Main Thread
    void queue_task(std::function<void()> task);
    
    // Main thread calls this to execute pending tasks
    void process_pending();

    // Get the event handle for the LwIP thread to wait on
    HANDLE get_event_handle() { return m_event; }

private:
    std::mutex m_mtx;
    std::vector<std::function<void()>> m_queue;
    HANDLE m_event;
};

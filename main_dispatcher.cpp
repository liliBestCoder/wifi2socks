#include "main_dispatcher.h"

MainDispatcher& MainDispatcher::instance() {
    static MainDispatcher inst;
    return inst;
}

void MainDispatcher::queue_task(std::function<void()> task) {
    std::lock_guard<std::mutex> lk(m_mtx);
    m_queue.push_back(task);
}

void MainDispatcher::process_pending() {
    std::vector<std::function<void()>> tasks;
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_queue.empty()) return;
        tasks.swap(m_queue);
    }
    for (auto& task : tasks) {
        task();
    }
}

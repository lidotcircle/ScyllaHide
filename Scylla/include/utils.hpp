#ifndef _UTILS_HPP_
#define _UTILS_HPP_

#include <type_traits>
#include <iterator>
#include <stdexcept>

template <typename FUNC>
struct deferred_call
{
    deferred_call(const deferred_call& that) = delete;
    deferred_call& operator=(const deferred_call& that) = delete;

    deferred_call(FUNC&& f) 
        : m_func(std::forward<FUNC>(f)), m_bOwner(true) 
    {
    }

    deferred_call(deferred_call&& that)
        : m_func(std::move(that.m_func)), m_bOwner(that.m_bOwner)
    {
        that.m_bOwner = false;
    }

    ~deferred_call()
    {
        execute();
    }

    bool cancel()
    {
        bool bWasOwner = m_bOwner;
        m_bOwner = false;
        return bWasOwner;
    }

    bool execute()
    {
        const auto bWasOwner = m_bOwner;

        if (m_bOwner)
        {
            m_bOwner = false;
            m_func();
        }

        return bWasOwner;
    }

private:
    FUNC m_func;
    bool m_bOwner;
};

/**
 * !!! be carefully, this object should be keep in a scoped variable,
 * otherwise it will be destroyed immediately
 */
template <typename F>
deferred_call<F> defer(F&& f)
{
    return deferred_call<F>(std::forward<F>(f));
}

#endif // _UTILS_HPP_

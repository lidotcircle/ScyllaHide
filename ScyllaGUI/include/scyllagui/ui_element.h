#ifndef _SCYLLA_GUI_UI_ELEMENT_H_
#define _SCYLLA_GUI_UI_ELEMENT_H_


class UIElement
{
private:
    bool m_visible;

public:
    UIElement();

    virtual bool show() = 0;

    bool& visibility();

    virtual ~UIElement();
};

#endif // _SCYLLA_GUI_UI_ELEMENT_H_
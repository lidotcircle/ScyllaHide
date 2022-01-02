#include "scyllagui/ui_element.h"


UIElement::UIElement(): m_visible(true) {}

bool& UIElement::visibility() {
    return this->m_visible;
}

UIElement::~UIElement() {}

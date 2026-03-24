use adw::prelude::*;

const BUFFER_ID: &str = "log-buffer-view";

pub fn build_view() -> gtk::Box {
    let view = gtk::Box::new(gtk::Orientation::Vertical, 0);

    // Inline header with clear button
    let header_box = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    header_box.set_margin_start(16);
    header_box.set_margin_end(16);
    header_box.set_margin_top(12);
    header_box.set_margin_bottom(8);

    let title = gtk::Label::builder()
        .label("Operation Logs")
        .css_classes(["title-4"])
        .halign(gtk::Align::Start)
        .hexpand(true)
        .build();
    header_box.append(&title);

    let clear_btn = gtk::Button::builder()
        .icon_name("edit-clear-symbolic")
        .tooltip_text("Clear logs")
        .build();
    header_box.append(&clear_btn);

    view.append(&header_box);

    // Text view in scrolled window
    let text_view = gtk::TextView::builder()
        .editable(false)
        .cursor_visible(false)
        .monospace(true)
        .wrap_mode(gtk::WrapMode::WordChar)
        .left_margin(16)
        .right_margin(16)
        .top_margin(8)
        .bottom_margin(8)
        .vexpand(true)
        .build();
    text_view.set_widget_name(BUFFER_ID);

    let scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::Automatic)
        .vexpand(true)
        .child(&text_view)
        .build();

    // Clear button clears the buffer
    let buffer = text_view.buffer();
    clear_btn.connect_clicked(move |_| {
        buffer.set_text("");
    });

    view.append(&scrolled);

    view
}

pub fn get_text_view(view: &gtk::Box) -> gtk::TextView {
    fn walk(widget: &gtk::Widget) -> Option<gtk::TextView> {
        if widget.widget_name() == BUFFER_ID {
            return widget.downcast_ref::<gtk::TextView>().cloned();
        }
        let mut child = widget.first_child();
        while let Some(c) = child {
            if let Some(found) = walk(&c) {
                return Some(found);
            }
            child = c.next_sibling();
        }
        None
    }
    walk(view.upcast_ref()).expect("Log text view not found")
}

pub fn append(text_view: &gtk::TextView, text: &str) {
    let buffer = text_view.buffer();
    let mut end = buffer.end_iter();
    buffer.insert(&mut end, text);

    // Auto-scroll: place mark at end and scroll to it
    let end = buffer.end_iter();
    let mark = if let Some(mark) = buffer.mark("end-mark") {
        buffer.move_mark(&mark, &end);
        mark
    } else {
        buffer.create_mark(Some("end-mark"), &end, false)
    };
    text_view.scroll_mark_onscreen(&mark);
}

use scripting additions

on run argv
    if (count of argv) is not 2 then
        error "usage: display-notification.applescript TITLE MESSAGE"
    end if

    set appTitle to item 1 of argv
    set notificationMessage to item 2 of argv
    display notification notificationMessage with title appTitle
end run

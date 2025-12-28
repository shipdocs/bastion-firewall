#!/bin/bash
#
# Launch Bastion GUI for all logged-in graphical users
# Called by systemd service when daemon starts
#

# Small delay to ensure daemon is fully ready
sleep 1

# Lock files are handled by the python script (stale check)
# Do not remove them blindly as it causes race conditions
# rm -f /tmp/bastion-gui-*.lock 2>/dev/null

# Find all logged-in graphical sessions and launch GUI for each
for session in $(loginctl list-sessions --no-legend | awk '{print $1}'); do
    # Get session details
    session_type=$(loginctl show-session "$session" -p Type --value 2>/dev/null)
    session_state=$(loginctl show-session "$session" -p State --value 2>/dev/null)
    session_user=$(loginctl show-session "$session" -p Name --value 2>/dev/null)
    
    # Only launch for active graphical sessions (x11 or wayland)
    if [[ "$session_type" == "x11" || "$session_type" == "wayland" ]] && [[ "$session_state" == "active" ]]; then
        if [ -n "$session_user" ]; then
            # Get user's UID and home directory
            user_uid=$(id -u "$session_user" 2>/dev/null)
            user_home=$(getent passwd "$session_user" | cut -d: -f6)
            
            if [ -z "$user_uid" ] || [ -z "$user_home" ]; then
                echo "Could not get user details for $session_user"
                continue
            fi
            
            # Check if GUI is already running for this user
            if pgrep -u "$session_user" -f "bastion-gui" > /dev/null 2>&1; then
                echo "GUI already running for user $session_user"
                continue
            fi
            
            echo "Launching GUI for user $session_user (session type: $session_type)"
            
            # Use systemd-run to launch as the user in their session
            # This properly inherits the user's environment
            systemd-run --user --machine="${session_user}@.host" \
                --setenv=QT_QPA_PLATFORM=wayland \
                /usr/bin/bastion-gui

            # Alternative fallback if systemd-run doesn't work
            if [ $? -ne 0 ]; then
                echo "systemd-run failed, trying direct launch..."
                
                if [[ "$session_type" == "wayland" ]]; then
                    sudo -u "$session_user" env \
                        XDG_RUNTIME_DIR="/run/user/$user_uid" \
                        WAYLAND_DISPLAY="wayland-0" \
                        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$user_uid/bus" \
                        QT_QPA_PLATFORM="wayland;xcb" \
                        setsid /usr/bin/bastion-gui </dev/null >/tmp/bastion-gui-$session_user.log 2>&1 &
                else
                    display=$(loginctl show-session "$session" -p Display --value 2>/dev/null)
                    display="${display:-:0}"
                    sudo -u "$session_user" env \
                        DISPLAY="$display" \
                        XAUTHORITY="$user_home/.Xauthority" \
                        XDG_RUNTIME_DIR="/run/user/$user_uid" \
                        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$user_uid/bus" \
                        setsid /usr/bin/bastion-gui </dev/null >/tmp/bastion-gui-$session_user.log 2>&1 &
                fi
            fi
            
            echo "GUI launch initiated for $session_user"
        fi
    fi
done

exit 0

<%inherit file="root.mako" />
<%def name="title()">Allow Access</%def>

<div class="consent" class="block">
    Allow access to ${relaying_party}<br>
    Select the information you want to share with ${relaying_party}.
    % if policy_uri:
        Please review the ${relaying_part} <a href="${policy_uri}"><b>privacy policy</b></a>
    % endif

    <form action="${action}" method="post" class="consent form">
        <input type="hidden" name="query" value="${query}"/>
        <table>
            <tr>
                <td>Username</td><td>${uid}</td><td><button></button></td>
            </tr>
            <tr>
                <td>Password</td>
                <td><input type="password" name="password"
                value="${password}"/></td>
            </tr>
            <tr>
                </td>
                <td><input type="submit" name="form.commit"
                        value="Log In"/></td>
            </tr>
        </table>
    </form>
    % if logo_url:
        <img src="${logo_uri}" alt="Client logo">
    % endif
</div>

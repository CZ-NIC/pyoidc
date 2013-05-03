<%inherit file="root.mako" />
<%def name="title()">Log in</%def>

<div class="login_form" class="block">
    <form action="${action}" method="post" class="login form">
        <input type="hidden" name="query" value="${query}"/>
        <table>
            <tr>
                <td>Username</td>
                <td><input type="text" name="login" value="${login}"/></td>
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
        <img src="${logo_url}" alt="Client logo">
    % endif
    % if policy_url:
        <a href="${policy_url}"><b>Client policy</b></a>
    % endif
</div>

<%def name="add_js()">
    <script type="text/javascript">
        $(document).ready(function() {
            bookie.login.init();
        });
    </script>
</%def>

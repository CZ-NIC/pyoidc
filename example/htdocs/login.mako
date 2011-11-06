<%inherit file="root.mako" />

<%def name="title()">Log in</%def>

<div class="login_form" class="block">
    <form action="${action}" method="post" class="login form">
        <input type="hidden" name="sid" value="${sid}"/>
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
                <td/>
                <td><input type="submit" name="form.submitted"
                    value="Log In"/></td>
            </tr>
        </table>
    </form>
</div>

<%def name="add_js()">
    <script type="text/javascript">
        $(document).ready(function() {
            bookie.login.init();
        });
    </script>
</%def>

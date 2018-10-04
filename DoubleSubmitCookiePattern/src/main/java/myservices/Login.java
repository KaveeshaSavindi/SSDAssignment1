package myservices;

import javax.servlet.ServletException;
import javax.servlet.http.*;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;


public class Login extends HttpServlet{
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        reqService(req, resp);
    }

    private static String generateCSRFToken(){
        String CSRFToken = null;
        byte[] bytes = new byte[16];
        try {
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();//only works with Java 8
            secureRandom.nextBytes(bytes);
            CSRFToken = new String(Base64.getEncoder().encode(bytes));//only works with Java 8
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return CSRFToken;
    }


    protected void reqService(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("text/html;charset=UTF-8");
        PrintWriter out = resp.getWriter();

        try {
            String username = req.getParameter("username");
            String password = req.getParameter("password");

            Cookie[] cookies = req.getCookies();//request for auto generated cookies in the browser
            cookies[0].setPath("/");

            if (username.equals("admin") && password.equals("admin")) {
                HttpSession session = req.getSession();
                session.setAttribute("username", username);
                String csrfToken = generateCSRFToken();
                System.out.println("Generated Token : "+csrfToken);
                Cookie c1 = new Cookie(cookies[0].getValue(), csrfToken);//double submit parts
                cookies[0].setValue(csrfToken);
                cookies[0].setPath("/");
                resp.addCookie(c1);
                session.setAttribute("csrfToken", csrfToken);//double submit parts
                resp.sendRedirect("home.jsp");
            } else {
                out.println("Invalid username or password. Username: admin Password:admin");
            }
        }finally {
            out.close();
        }

    }
}

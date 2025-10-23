# 613 mistakes out of 2249

Sorted by confidence. Every row is a test-family alert the model never trained on.

> Scored with `--no-gen`, so the model's WHY and FIX text is empty; the code and the confidence are the evidence.

## 1. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getCookies_Servlet_02.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getCookies_Servlet_02 extends AbstractTestCaseServlet
{

    private void funcB1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (true)
        {
            data = ""; /* initialize data in case there are no cookies */
            /* Read data from cookies */
            {
                Cookie cookieSources[] = request.getCookies();
                if (cookieSources != null)
                {
                    
                    data = cookieSources[0].getValue();
                }
            }
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (true)
        {
            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
    
```

## 2. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getCookies_Servlet_04.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getCookies_Servlet_04 extends AbstractTestCaseServlet
{

    private void funcA1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE)
        {
            data = ""; /* initialize data in case there are no cookies */
            /* Read data from cookies */
            {
                Cookie cookieSources[] = request.getCookies();
                if (cookieSources != null)
                {
                    
                    data = cookieSources[0].getValue();
                }
            }
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (PRIVATE_STATIC_FINAL_TRUE)
        {
            String xmlFile = null;
            if(System.getProperty("os.name
```

## 3. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getQueryString_Servlet_02.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import java.util.StringTokenizer;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getQueryString_Servlet_02 extends AbstractTestCaseServlet
{

    private void funcB1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (true)
        {
            data = ""; /* initialize data in case id is not in query string */
            
            {
                StringTokenizer tokenizer = new StringTokenizer(request.getQueryString(), "&");
                while (tokenizer.hasMoreTokens())
                {
                    String token = tokenizer.nextToken(); /* a token will be like "id=foo" */
                    if(token.startsWith("id=")) /* check if we have the "id" parameter" */
                    {
                        data = token.substring(3); /* set data to "foo" */
                        break; /* exit while loop */
                    }
                }
            }
        }
        else
        {
            /* I
```

## 4. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getCookies_Servlet_02.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getCookies_Servlet_02 extends AbstractTestCaseServlet
{

    private void funcA1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (true)
        {
            data = ""; /* initialize data in case there are no cookies */
            /* Read data from cookies */
            {
                Cookie cookieSources[] = request.getCookies();
                if (cookieSources != null)
                {
                    
                    data = cookieSources[0].getValue();
                }
            }
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (false)
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
            IO.writeLine("Benign, fixed
```

## 5. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getCookies_Servlet_03.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getCookies_Servlet_03 extends AbstractTestCaseServlet
{

    private void funcA1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (5==5)
        {
            data = ""; /* initialize data in case there are no cookies */
            /* Read data from cookies */
            {
                Cookie cookieSources[] = request.getCookies();
                if (cookieSources != null)
                {
                    
                    data = cookieSources[0].getValue();
                }
            }
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (5==5)
        {
            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
    
```

## 6. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getCookies_Servlet_05.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getCookies_Servlet_05 extends AbstractTestCaseServlet
{

    private void funcB1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (privateTrue)
        {
            data = ""; /* initialize data in case there are no cookies */
            /* Read data from cookies */
            {
                Cookie cookieSources[] = request.getCookies();
                if (cookieSources != null)
                {
                    
                    data = cookieSources[0].getValue();
                }
            }
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (privateTrue)
        {
            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().indexOf("wi
```

## 7. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getCookies_Servlet_08.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getCookies_Servlet_08 extends AbstractTestCaseServlet
{

    private void funcA1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (privateReturnsTrue())
        {
            data = ""; /* initialize data in case there are no cookies */
            /* Read data from cookies */
            {
                Cookie cookieSources[] = request.getCookies();
                if (cookieSources != null)
                {
                    
                    data = cookieSources[0].getValue();
                }
            }
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (privateReturnsTrue())
        {
            String xmlFile = null;
            if(System.getProperty("os.name").toLower
```

## 8. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getCookies_Servlet_09.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getCookies_Servlet_09 extends AbstractTestCaseServlet
{

    private void funcA1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (IO.STATIC_FINAL_TRUE)
        {
            data = ""; /* initialize data in case there are no cookies */
            /* Read data from cookies */
            {
                Cookie cookieSources[] = request.getCookies();
                if (cookieSources != null)
                {
                    
                    data = cookieSources[0].getValue();
                }
            }
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (IO.STATIC_FINAL_TRUE)
        {
            String xmlFile = null;
            if(System.getProperty("os.name").toLower
```

## 9. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getCookies_Servlet_10.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getCookies_Servlet_10 extends AbstractTestCaseServlet
{

    private void funcB1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (IO.staticTrue)
        {
            data = ""; /* initialize data in case there are no cookies */
            /* Read data from cookies */
            {
                Cookie cookieSources[] = request.getCookies();
                if (cookieSources != null)
                {
                    
                    data = cookieSources[0].getValue();
                }
            }
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (IO.staticTrue)
        {
            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().indexOf
```

## 10. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getCookies_Servlet_11.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getCookies_Servlet_11 extends AbstractTestCaseServlet
{

    private void funcA1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (IO.staticReturnsTrue())
        {
            data = ""; /* initialize data in case there are no cookies */
            /* Read data from cookies */
            {
                Cookie cookieSources[] = request.getCookies();
                if (cookieSources != null)
                {
                    
                    data = cookieSources[0].getValue();
                }
            }
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (IO.staticReturnsTrue())
        {
            String xmlFile = null;
            if(System.getProperty("os.name").toL
```

## 11. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getParameter_Servlet_02.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getParameter_Servlet_02 extends AbstractTestCaseServlet
{

    private void funcA1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (true)
        {
            
            data = request.getParameter("name");
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (false)
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
            IO.writeLine("Benign, fixed string");
        }
        else
        {

            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
            {
                /* running on Windows */
                xmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_I
```

## 12. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getParameter_Servlet_02.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getParameter_Servlet_02 extends AbstractTestCaseServlet
{

    private void funcB1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (true)
        {
            
            data = request.getParameter("name");
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (true)
        {
            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
            {
                /* running on Windows */
                xmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            }
            else
            {
                /* running on non-Windows */
                xmlFile = "./src/testcases/CWE643_X
```

## 13. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getParameter_Servlet_04.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getParameter_Servlet_04 extends AbstractTestCaseServlet
{

    private void funcA1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE)
        {
            
            data = request.getParameter("name");
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (PRIVATE_STATIC_FINAL_FALSE)
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
            IO.writeLine("Benign, fixed string");
        }
        else
        {

            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
            {
                /* running on Windows */
                xmlFile = "\\src\\testcas
```

## 14. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getParameter_Servlet_04.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getParameter_Servlet_04 extends AbstractTestCaseServlet
{

    private void funcB1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE)
        {
            
            data = request.getParameter("name");
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (PRIVATE_STATIC_FINAL_TRUE)
        {
            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
            {
                /* running on Windows */
                xmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            }
            else
            {
                /* running on non-Windows */
         
```

## 15. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getParameter_Servlet_05.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getParameter_Servlet_05 extends AbstractTestCaseServlet
{

    private void funcB1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (privateTrue)
        {
            
            data = request.getParameter("name");
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (privateTrue)
        {
            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
            {
                /* running on Windows */
                xmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            }
            else
            {
                /* running on non-Windows */
                xmlFile = "./src/test
```

## 16. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getParameter_Servlet_06.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getParameter_Servlet_06 extends AbstractTestCaseServlet
{

    private void funcA1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE==5)
        {
            
            data = request.getParameter("name");
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (PRIVATE_STATIC_FINAL_FIVE==5)
        {
            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
            {
                /* running on Windows */
                xmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            }
            else
            {
                /* running on non-Windows */
   
```

## 17. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getParameter_Servlet_07.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getParameter_Servlet_07 extends AbstractTestCaseServlet
{

    private void funcA1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (privateFive==5)
        {
            
            data = request.getParameter("name");
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (privateFive==5)
        {
            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
            {
                /* running on Windows */
                xmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            }
            else
            {
                /* running on non-Windows */
                xmlFile = "./sr
```

## 18. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getParameter_Servlet_08.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getParameter_Servlet_08 extends AbstractTestCaseServlet
{

    private void funcA1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (privateReturnsTrue())
        {
            
            data = request.getParameter("name");
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (privateReturnsTrue())
        {
            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
            {
                /* running on Windows */
                xmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            }
            else
            {
                /* running on non-Windows */
                xml
```

## 19. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getParameter_Servlet_09.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getParameter_Servlet_09 extends AbstractTestCaseServlet
{

    private void funcA1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (IO.STATIC_FINAL_TRUE)
        {
            
            data = request.getParameter("name");
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (IO.STATIC_FINAL_TRUE)
        {
            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
            {
                /* running on Windows */
                xmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            }
            else
            {
                /* running on non-Windows */
                xml
```

## 20. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getParameter_Servlet_10.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getParameter_Servlet_10 extends AbstractTestCaseServlet
{

    private void funcB1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (IO.staticTrue)
        {
            
            data = request.getParameter("name");
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (IO.staticTrue)
        {
            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
            {
                /* running on Windows */
                xmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            }
            else
            {
                /* running on non-Windows */
                xmlFile = "./src/
```

## 21. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getParameter_Servlet_11.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getParameter_Servlet_11 extends AbstractTestCaseServlet
{

    private void funcA1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (IO.staticReturnsTrue())
        {
            
            data = request.getParameter("name");
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (IO.staticReturnsTrue())
        {
            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
            {
                /* running on Windows */
                xmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            }
            else
            {
                /* running on non-Windows */
               
```

## 22. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getQueryString_Servlet_02.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import java.util.StringTokenizer;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getQueryString_Servlet_02 extends AbstractTestCaseServlet
{

    private void funcA1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (true)
        {
            data = ""; /* initialize data in case id is not in query string */
            
            {
                StringTokenizer tokenizer = new StringTokenizer(request.getQueryString(), "&");
                while (tokenizer.hasMoreTokens())
                {
                    String token = tokenizer.nextToken(); /* a token will be like "id=foo" */
                    if(token.startsWith("id=")) /* check if we have the "id" parameter" */
                    {
                        data = token.substring(3); /* set data to "foo" */
                        break; /* exit while loop */
                    }
                }
            }
        }
        else
        {
            /* I
```

## 23. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getQueryString_Servlet_05.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import java.util.StringTokenizer;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getQueryString_Servlet_05 extends AbstractTestCaseServlet
{

    private void funcA1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (privateTrue)
        {
            data = ""; /* initialize data in case id is not in query string */
            
            {
                StringTokenizer tokenizer = new StringTokenizer(request.getQueryString(), "&");
                while (tokenizer.hasMoreTokens())
                {
                    String token = tokenizer.nextToken(); /* a token will be like "id=foo" */
                    if(token.startsWith("id=")) /* check if we have the "id" parameter" */
                    {
                        data = token.substring(3); /* set data to "foo" */
                        break; /* exit while loop */
                    }
                }
            }
        }
        else
        {
         
```

## 24. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getQueryString_Servlet_10.java`
- truth: FP, model: TP (p_tp 1.000)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import java.util.StringTokenizer;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getQueryString_Servlet_10 extends AbstractTestCaseServlet
{

    private void funcB1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (IO.staticTrue)
        {
            data = ""; /* initialize data in case id is not in query string */
            
            {
                StringTokenizer tokenizer = new StringTokenizer(request.getQueryString(), "&");
                while (tokenizer.hasMoreTokens())
                {
                    String token = tokenizer.nextToken(); /* a token will be like "id=foo" */
                    if(token.startsWith("id=")) /* check if we have the "id" parameter" */
                    {
                        data = token.substring(3); /* set data to "foo" */
                        break; /* exit while loop */
                    }
                }
            }
        }
        else
        {
       
```

## 25. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getCookies_Servlet_07.java`
- truth: FP, model: TP (p_tp 0.999)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getCookies_Servlet_07 extends AbstractTestCaseServlet
{

    private void funcA1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (privateFive==5)
        {
            data = ""; /* initialize data in case there are no cookies */
            /* Read data from cookies */
            {
                Cookie cookieSources[] = request.getCookies();
                if (cookieSources != null)
                {
                    
                    data = cookieSources[0].getValue();
                }
            }
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (privateFive==5)
        {
            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().index
```

## 26. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getCookies_Servlet_14.java`
- truth: FP, model: TP (p_tp 0.999)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getCookies_Servlet_14 extends AbstractTestCaseServlet
{

    private void funcA1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (IO.staticFive==5)
        {
            data = ""; /* initialize data in case there are no cookies */
            /* Read data from cookies */
            {
                Cookie cookieSources[] = request.getCookies();
                if (cookieSources != null)
                {
                    
                    data = cookieSources[0].getValue();
                }
            }
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (IO.staticFive==5)
        {
            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().i
```

## 27. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getParameter_Servlet_03.java`
- truth: FP, model: TP (p_tp 0.999)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getParameter_Servlet_03 extends AbstractTestCaseServlet
{

    private void funcA1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (5==5)
        {
            
            data = request.getParameter("name");
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (5==5)
        {
            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
            {
                /* running on Windows */
                xmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            }
            else
            {
                /* running on non-Windows */
                xmlFile = "./src/testcases/CWE643_X
```

## 28. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getParameter_Servlet_05.java`
- truth: FP, model: TP (p_tp 0.999)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getParameter_Servlet_05 extends AbstractTestCaseServlet
{

    private void funcB1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;

        if (privateTrue)
        {
            
            data = request.getParameter("name");
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (privateFalse)
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
            IO.writeLine("Benign, fixed string");
        }
        else
        {

            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
            {
                /* running on Windows */
                xmlFile = "\\src\\testcases\\CWE643_Xpath Injection\
```

## 29. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getParameter_Servlet_06.java`
- truth: FP, model: TP (p_tp 0.999)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getParameter_Servlet_06 extends AbstractTestCaseServlet
{

    private void funcA1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE==5)
        {
            
            data = request.getParameter("name");
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (PRIVATE_STATIC_FINAL_FIVE!=5)
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
            IO.writeLine("Benign, fixed string");
        }
        else
        {

            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
            {
                /* running on Windows */
                xmlFile = "\\src\\te
```

## 30. CWE-643 java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request

- file: `src/testcases/CWE643_Xpath_Injection/CWE643_Xpath_Injection__getParameter_Servlet_09.java`
- truth: FP, model: TP (p_tp 0.999)
- why: 
- fix: 

```java
package testcases.CWE643_Xpath_Injection;
import testcasesupport.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.apache.commons.lang.StringEscapeUtils;

public class CWE643_Xpath_Injection__getParameter_Servlet_09 extends AbstractTestCaseServlet
{

    private void funcA1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        if (IO.STATIC_FINAL_TRUE)
        {
            
            data = request.getParameter("name");
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (IO.STATIC_FINAL_FALSE)
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
            IO.writeLine("Benign, fixed string");
        }
        else
        {

            String xmlFile = null;
            if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
            {
                /* running on Windows */
                xmlFile = "\\src\\testcases\\CWE643
```

import { questionsArr1 , questionsArr2 } from "./constants.js";

let questions = questionsArr1
const quizContainer = document.getElementById('quiz');
const submitBtn = document.getElementById('submitBtn');
const questionBank1Radio = document.getElementById('questionBank1');
const questionBank2Radio = document.getElementById('questionBank2');
questionBank1Radio.checked = true;

function generateQuiz() {
    let quizHTML = '';
    questions.forEach(question => {
        quizHTML += `
                    <div class="question">
                        <h3>Question ${question['Question No'] ?? question['S.No']}:</h3>
                        <p>${question['Question']}</p>
                        <div class="options">
                `;
        for (let i = 1; i <= 4; i++) {
            if (question[`Option ${i}`]) {
                quizHTML += `
                            <div class="option">
                                <input type="radio" name="question${question['Question No'] ?? question['S.No']}" value="${question[`Option ${i}`]}">
                                <label>${question[`Option ${i}`]}</label>
                            </div>
                        `;
            }
        }
        quizHTML += `</div></div>`;
    });
    quizContainer.innerHTML = quizHTML;
}

generateQuiz();

function handleRadioButtonChange() {
    if (questionBank1Radio.checked) {
        // If questionBank1 radio button is selected
        console.log('Question Bank 1 selected');
        questions = questionsArr1; // Update questions variable with questionsArr1
    } else if (questionBank2Radio.checked) {
        // If questionBank2 radio button is selected
        console.log('Question Bank 2 selected');
        questions = questionsArr2; // Update questions variable with questionsArr2
    }
    generateQuiz(); // Call generateQuiz() to regenerate the quiz with the new set of questions
}


// Add event listener to questionBank1 radio button
questionBank1Radio.addEventListener('change', handleRadioButtonChange);

// Add event listener to questionBank2 radio button
questionBank2Radio.addEventListener('change', handleRadioButtonChange);

submitBtn.addEventListener('click', () => {
    let totalMarks = 0;
    let incorrectAnswers = [];

    questions.forEach(question => {
        const selectedOption = document.querySelector(`input[name="question${question['Question No'] ?? question['S.No']}"]:checked`);
        if (selectedOption) {
            if (selectedOption.value === question['Correct answer']) {
                totalMarks++;
            } else {
                incorrectAnswers.push({
                    questionNumber: question['Question No'] ?? question['S.No'],
                    correctAnswer: question['Correct answer']
                });
            }
        }
    });

    // Display total marks and incorrect answers
    let resultHTML = `<h2>Result</h2>`;
    resultHTML += `<p>Total Marks: ${totalMarks}/${questions.length}</p>`;
    if (incorrectAnswers.length > 0) {
        resultHTML += `<p>Incorrect Answers:</p>`;
        incorrectAnswers.forEach(answer => {
            resultHTML += `<p>Question ${answer.questionNumber}: Correct answer is ${answer.correctAnswer}</p>`;
        });
    } else {
        resultHTML += `<p>Congratulations! You answered all questions correctly.</p>`;
    }

    // Append result to the quiz container
    quizContainer.innerHTML += resultHTML;
});
